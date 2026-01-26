defmodule AgentReviews.Repo do
  @moduledoc false

  @agent_dir ".agent_review"

  def git_root(nil), do: git_root(".")

  def git_root(path) do
    path = Path.expand(to_string(path))

    if File.dir?(path) do
      case System.cmd("git", ["rev-parse", "--show-toplevel"], cd: path, stderr_to_stdout: true) do
        {out, 0} -> {:ok, String.trim(out)}
        {out, _} -> {:error, "Not in a git repository: #{path}\n\nOutput:\n#{out}"}
      end
    else
      {:error, "Repo path does not exist or is not a directory: #{path}"}
    end
  end

  def git_common_root(root) do
    case System.cmd("git", ["rev-parse", "--git-common-dir"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        p = String.trim(out)
        p = if Path.type(p) == :absolute, do: p, else: Path.join(root, p)
        {:ok, Path.dirname(p)}

      {out, _} ->
        {:error, "Failed to determine git common dir.\n\nOutput:\n#{out}"}
    end
  end

  def ensure_repo_local_exclude(root) do
    case repo_local_exclude_path(root) do
      {:ok, exclude_path} ->
        content =
          case File.read(exclude_path) do
            {:ok, s} -> s
            _ -> ""
          end

        needs_agent? = not Regex.match?(~r/^\s*\.agent_review\/\s*$/m, content)
        needs_worktrees? = not Regex.match?(~r/^\s*\.worktrees\/\s*$/m, content)

        if not (needs_agent? or needs_worktrees?) do
          :ok
        else
          File.mkdir_p!(Path.dirname(exclude_path))

          lines =
            [
              if(String.trim(content) == "", do: "", else: "\n"),
              "# agent_reviews (local-only)\n",
              if(needs_agent?, do: "#{@agent_dir}/\n", else: ""),
              if(needs_worktrees?, do: ".worktrees/\n", else: "")
            ]
            |> IO.iodata_to_binary()

          File.write!(exclude_path, content <> lines)

          added =
            []
            |> then(fn acc -> if(needs_agent?, do: ["#{@agent_dir}/" | acc], else: acc) end)
            |> then(fn acc -> if(needs_worktrees?, do: [".worktrees/" | acc], else: acc) end)
            |> Enum.reverse()
            |> Enum.join(", ")

          IO.puts(:stderr, "INFO: Added #{added} to repo-local exclude: #{exclude_path}")
          :ok
        end

      {:error, _} ->
        :ok
    end
  rescue
    e in [File.Error] ->
      p = e.path
      r = e.reason

      hint =
        cond do
          is_binary(p) and String.trim(p) != "" ->
            " Add them manually by appending `#{@agent_dir}/` and `.worktrees/` to #{p}."

          true ->
            " Add them manually by appending `#{@agent_dir}/` and `.worktrees/` to `.git/info/exclude`."
        end

      IO.puts(:stderr, "WARN: Could not write repo-local exclude (#{inspect(r)})." <> hint)
      :ok

    e ->
      IO.puts(:stderr, "WARN: Failed to update repo-local exclude: #{Exception.message(e)}")
      :ok
  end

  defp repo_local_exclude_path(root) do
    case System.cmd("git", ["rev-parse", "--git-path", "info/exclude"],
           cd: root,
           stderr_to_stdout: true
         ) do
      {out, 0} ->
        p = String.trim(out)
        p = if Path.type(p) == :absolute, do: p, else: Path.join(root, p)
        {:ok, p}

      _ ->
        {:error, :no_git}
    end
  end

  def ensure_gh_authed do
    with :ok <- AgentReviews.Runtime.ensure_cmd("gh") do
      case System.cmd("gh", ["auth", "status", "-h", "github.com"], stderr_to_stdout: true) do
        {_out, 0} ->
          :ok

        {out, _} ->
          {:error, "GitHub CLI not authenticated. Run: gh auth login\n\nOutput:\n#{out}"}
      end
    end
  end

  # ----- PR checkout (gh pr checkout) -----

  def checkout_pr_branch(root, pr_ref) do
    with :ok <- ensure_gh_authed(),
         {:ok, {_owner, _repo, number}} <- parse_pr_ref(pr_ref, root),
         {:ok, head_sha} <- gh_pr_head_sha(root, number),
         :ok <- gh_pr_checkout(root, number),
         :ok <- ensure_contains_pr_head_commit(root, "", head_sha),
         {:ok, branch} <- current_branch(root) do
      IO.puts(:stderr, "INFO: Checked out PR #{number} branch: #{branch}")

      {:ok,
       %{
         pr_number: number,
         branch: branch,
         head_sha: head_sha
       }}
    end
  end

  defp current_branch(root) do
    case System.cmd("git", ["rev-parse", "--abbrev-ref", "HEAD"],
           cd: root,
           stderr_to_stdout: true
         ) do
      {out, 0} -> {:ok, String.trim(out)}
      {out, _} -> {:error, "Failed to determine current git branch.\n\nOutput:\n#{out}"}
    end
  end

  defp gh_pr_head_sha(root, number) do
    {out, status} =
      System.cmd("gh", ["pr", "view", Integer.to_string(number), "--json", "headRefOid"],
        cd: root,
        stderr_to_stdout: true
      )

    if status != 0 do
      {:error, "Failed to query PR head SHA via gh.\n\nOutput:\n#{out}"}
    else
      with {:ok, decoded} <- Jason.decode(out),
           oid when is_binary(oid) <- Map.get(decoded, "headRefOid") do
        {:ok, oid}
      else
        _ -> {:error, "Malformed gh pr view JSON while reading headRefOid."}
      end
    end
  end

  defp gh_pr_checkout(root, number) do
    {out, status} =
      System.cmd("gh", ["pr", "checkout", Integer.to_string(number)],
        cd: root,
        stderr_to_stdout: true
      )

    if status == 0 do
      :ok
    else
      {:error, "Failed to checkout PR via gh.\n\nOutput:\n#{out}"}
    end
  end

  def ensure_contains_pr_head_commit(_root, _head_ref, ""), do: :ok

  def ensure_contains_pr_head_commit(root, head_ref, head_sha) do
    case System.cmd("git", ["merge-base", "--is-ancestor", head_sha, "HEAD"],
           cd: root,
           stderr_to_stdout: true
         ) do
      {_out, 0} ->
        :ok

      {out, _} ->
        {:error,
         "Current HEAD does not contain the PR head commit #{inspect(head_sha)} (branch #{inspect(head_ref)}).\n\nOutput:\n#{out}"}
    end
  end

  # ----- Worktrees (optional) -----

  def ensure_pr_worktree_root(root, pr_ref, opts) do
    with {:ok, {_owner, _repo, number}} <- parse_pr_ref(pr_ref, root),
         {:ok, base} <- worktree_base_dir(opts),
         wt_root <- Path.join(base, "pr-#{number}"),
         :ok <- ensure_worktree_exists(Map.get(opts, :common_root) || root, wt_root) do
      {:ok, wt_root}
    end
  end

  defp worktree_base_dir(opts) do
    common_root = Map.get(opts, :common_root) || "."

    base =
      case Map.get(opts, :worktree_dir) do
        nil ->
          Path.join([common_root, ".worktrees", AgentReviews.Runtime.invoke_name()])

        dir ->
          dir = Path.expand(to_string(dir))
          if Path.type(dir) == :absolute, do: dir, else: Path.join(common_root, dir)
      end

    {:ok, base}
  end

  defp ensure_worktree_exists(common_root, wt_root) do
    if File.exists?(wt_root) do
      validate_worktree_root(wt_root)
    else
      File.mkdir_p!(Path.dirname(wt_root))

      {out, status} =
        System.cmd("git", ["worktree", "add", wt_root], cd: common_root, stderr_to_stdout: true)

      if status == 0 do
        IO.puts(:stderr, "INFO: Created worktree: #{wt_root}")
        :ok
      else
        {:error, "Failed to create worktree at #{wt_root}.\n\nOutput:\n#{out}"}
      end
    end
  end

  defp validate_worktree_root(wt_root) do
    case System.cmd("git", ["rev-parse", "--show-toplevel"], cd: wt_root, stderr_to_stdout: true) do
      {out, 0} ->
        expected = Path.expand(wt_root)
        actual = out |> String.trim() |> Path.expand()

        if actual == expected do
          :ok
        else
          {:error, "Path exists but is not the expected worktree root: #{wt_root}"}
        end

      {out, _} ->
        {:error, "Path exists but is not a git worktree: #{wt_root}\n\nOutput:\n#{out}"}
    end
  end

  # ----- PR ref parsing (pr number, URL, owner/repo#n) -----

  def parse_pr_ref(ref, root) do
    ref = String.trim(ref)

    case Integer.parse(ref) do
      {n, ""} ->
        with {:ok, {owner, repo}} <- infer_owner_repo_from_remote(root) do
          {:ok, {owner, repo, n}}
        end

      _ ->
        cond do
          String.starts_with?(ref, "http://") or String.starts_with?(ref, "https://") ->
            parse_pr_url(ref)

          String.contains?(ref, "#") and String.contains?(ref, "/") ->
            parse_owner_repo_hash(ref)

          true ->
            {:error, "Unrecognised PR reference: '#{ref}'"}
        end
    end
  end

  defp parse_pr_url(ref) do
    uri = URI.parse(ref)

    if uri.host != "github.com" or not is_binary(uri.path) do
      {:error, "Unrecognised PR URL: '#{ref}'"}
    else
      segments =
        uri.path
        |> String.trim_leading("/")
        |> String.split("/", trim: true)

      case segments do
        [owner, repo, "pull", number_str | _rest] ->
          case Integer.parse(number_str) do
            {n, ""} -> {:ok, {owner, repo, n}}
            _ -> {:error, "Unrecognised PR URL: '#{ref}'"}
          end

        _ ->
          {:error, "Unrecognised PR URL: '#{ref}'"}
      end
    end
  end

  defp parse_owner_repo_hash(ref) do
    case String.split(ref, "#", parts: 2) do
      [owner_repo, number_str] ->
        with [owner, repo] <- String.split(owner_repo, "/", parts: 2),
             true <- owner != "" and repo != "",
             {n, ""} <- Integer.parse(number_str) do
          {:ok, {owner, repo, n}}
        else
          _ -> {:error, "Unrecognised PR reference: '#{ref}'"}
        end

      _ ->
        {:error, "Unrecognised PR reference: '#{ref}'"}
    end
  end

  defp infer_owner_repo_from_remote(root) do
    candidates =
      case System.cmd("git", ["remote"], cd: root, stderr_to_stdout: true) do
        {out, 0} ->
          remotes =
            out
            |> String.split(["\r\n", "\n", "\r"], trim: true)
            |> Enum.map(&String.trim/1)
            |> Enum.reject(&(&1 == ""))

          ["origin" | Enum.reject(remotes, &(&1 == "origin"))]

        _ ->
          ["origin"]
      end

    found =
      Enum.find_value(candidates, fn name ->
        case System.cmd("git", ["remote", "get-url", name], cd: root, stderr_to_stdout: true) do
          {remote, 0} ->
            remote = String.trim(remote)

            case parse_github_remote(remote) do
              {:ok, owner, repo} -> {:ok, {owner, repo, name, remote}}
              :error -> nil
            end

          _ ->
            nil
        end
      end)

    case found do
      {:ok, {owner, repo, _name, _remote}} ->
        {:ok, {owner, repo}}

      nil ->
        has_any_remote? =
          case System.cmd("git", ["remote"], cd: root, stderr_to_stdout: true) do
            {out, 0} -> String.trim(out) != ""
            _ -> false
          end

        if has_any_remote? do
          {:error,
           "Could not infer GitHub repo from git remotes.\n\nFix:\n- Pass a PR URL: `https://github.com/<owner>/<repo>/pull/<n>`\n- Or pass `owner/repo#<n>`\n- Or add/rename a GitHub remote as `origin`.\n\nHint: run `git remote -v` in the target repo to see configured remotes."}
        else
          {:error,
           "Could not infer GitHub repo because this repo has no git remotes configured.\n\nFix:\n- Run inside the target repo (or pass `-C /path/to/repo`).\n- Or pass a PR URL: `https://github.com/<owner>/<repo>/pull/<n>`\n- Or pass `owner/repo#<n>`\n\nHint: run `git remote -v` in the target repo."}
        end
    end
  end

  defp parse_github_remote(remote) when is_binary(remote) do
    remote = String.trim(remote)

    cond do
      String.starts_with?(remote, "git@github.com:") ->
        rest = String.replace_prefix(remote, "git@github.com:", "")
        parse_owner_repo_path(rest)

      String.starts_with?(remote, "ssh://git@github.com/") ->
        rest = String.replace_prefix(remote, "ssh://git@github.com/", "")
        parse_owner_repo_path(rest)

      String.starts_with?(remote, "https://github.com/") ->
        rest = String.replace_prefix(remote, "https://github.com/", "")
        parse_owner_repo_path(rest)

      String.starts_with?(remote, "http://github.com/") ->
        rest = String.replace_prefix(remote, "http://github.com/", "")
        parse_owner_repo_path(rest)

      true ->
        :error
    end
  end

  defp parse_owner_repo_path(path) when is_binary(path) do
    path =
      path
      |> String.trim()
      |> String.trim_leading("/")
      |> String.trim_trailing("/")
      |> String.replace_suffix(".git", "")

    case String.split(path, "/", parts: 2) do
      [owner, repo] when owner != "" and repo != "" -> {:ok, owner, repo}
      _ -> :error
    end
  end
end
