#!/usr/bin/env elixir

defmodule CodexReviews do
  @agent_dir ".agent"

  def main(argv) do
    {opts, argv} = parse_opts(argv)
    invoke = invoke_name()
    opts = Map.put(opts, :invoke, invoke)

    if argv in [["--help"], ["-h"], ["help"]] do
      usage(invoke)
      :ok
    else
      with :ok <- ensure_cmd("git"),
           {:ok, root} <- git_root(Map.get(opts, :repo)),
           {:ok, common_root} <- git_common_root(root),
           {:ok, opts} <- load_effective_opts(common_root, Map.put(opts, :invoke, invoke)),
           opts <- Map.put(opts, :common_root, common_root) do
        argv
        |> dispatch(root, opts)
        |> halt_on_error()
      else
        {:error, msg} ->
          IO.puts(:stderr, "ERROR: #{msg}")
          System.halt(1)
      end
    end
  end

  defp parse_opts(argv) do
    parse_opts(
      argv,
      %{
        verbose?: false,
        verbose_overridden?: false,
        model: nil,
        reasoning_effort: nil,
        codex_config: [],
        post_fallback_top_level?: false,
        repo: nil,
        commit?: false,
        commit_overridden?: false,
        checkout: :unset,
        stash: :unset,
        stash_message: nil,
        config_paths: [],
        agent_cmd: nil,
        agent_args: nil,
        full_auto: nil,
        skip_nitpicks: nil,
        auto_commit: nil,
        checkout_default: nil,
        worktree?: false,
        worktree_dir: nil
      },
      []
    )
  end

  defp parse_opts([], opts, rest_rev), do: {opts, Enum.reverse(rest_rev)}

  defp parse_opts(["-C", path | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | repo: path}, rest_rev)

  defp parse_opts(["--repo", path | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | repo: path}, rest_rev)

  defp parse_opts(["--verbose" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | verbose?: true, verbose_overridden?: true}, rest_rev)

  defp parse_opts(["--quiet" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | verbose?: false, verbose_overridden?: true}, rest_rev)

  defp parse_opts(["--model", model | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | model: model}, rest_rev)

  defp parse_opts(["--reasoning-effort", effort | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | reasoning_effort: effort}, rest_rev)

  defp parse_opts(["--codex-config", kv | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | codex_config: opts.codex_config ++ [kv]}, rest_rev)

  defp parse_opts(["--fallback-top-level" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | post_fallback_top_level?: true}, rest_rev)

  defp parse_opts(["--checkout" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | checkout: true}, rest_rev)

  defp parse_opts(["--no-checkout" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | checkout: false}, rest_rev)

  defp parse_opts(["--stash" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | stash: true}, rest_rev)

  defp parse_opts(["--no-stash" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | stash: false}, rest_rev)

  defp parse_opts(["--stash-message", msg | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | stash_message: msg}, rest_rev)

  defp parse_opts(["--worktree" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | worktree?: true}, rest_rev)

  defp parse_opts(["--worktree-dir", dir | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | worktree_dir: dir}, rest_rev)

  defp parse_opts(["--config", path | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | config_paths: opts.config_paths ++ [path]}, rest_rev)

  defp parse_opts(["--commit" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | commit?: true, commit_overridden?: true}, rest_rev)

  defp parse_opts([other | rest], opts, rest_rev),
    do: parse_opts(rest, opts, [other | rest_rev])

  defp dispatch(argv, root, opts) do
    case argv do
      ["--help"] ->
        usage(opts.invoke)
        :ok

      ["-h"] ->
        usage(opts.invoke)
        :ok

      ["config"] ->
        print_config_summary(root, opts)
        :ok

      ["fetch", pr_ref] ->
        _ = ensure_repo_local_exclude(root)

        with_optional_checkout(root, pr_ref, :fetch, opts, fn checkout_ctx ->
          case run_fetch(root, pr_ref) do
            {:ok, fetch_ctx} ->
              fetch_ctx = Map.put(fetch_ctx, :checkout_ctx, checkout_ctx)
              print_fetch_summary(root, fetch_ctx, opts)
              {:ok, fetch_ctx}

            other ->
              other
          end
        end)

      ["apply"] ->
        _ = ensure_repo_local_exclude(root)

        case run_apply(root, opts) do
          {:ok, apply_ctx} ->
            case maybe_commit(root, apply_ctx.tasks_yaml, opts) do
              {:error, msg} ->
                {:error, msg}

              commit_ctx ->
                print_apply_summary(root, apply_ctx, commit_ctx, opts)
                {:ok, apply_ctx}
            end

          other ->
            other
        end

      ["run", pr_ref] ->
        if Map.get(opts, :worktree?, false) do
          _ = ensure_repo_local_exclude(Map.get(opts, :common_root) || root)

          with {:ok, wt_root} <- ensure_pr_worktree_root(root, pr_ref, opts) do
            IO.puts(:stderr, "INFO: Using worktree: #{wt_root}")
            _ = ensure_repo_local_exclude(wt_root)
            run_in_root(wt_root, pr_ref, opts)
          end
        else
          _ = ensure_repo_local_exclude(root)
          run_in_root(root, pr_ref, opts)
        end

      ["post", pr_ref] ->
        _ = ensure_repo_local_exclude(root)

        with_optional_checkout(root, pr_ref, :post, opts, fn _checkout_ctx ->
          case run_post(root, pr_ref, opts) do
            {:ok, post_ctx} ->
              print_post_summary(root, pr_ref, post_ctx, opts)
              {:ok, post_ctx}

            other ->
              other
          end
        end)

      _ ->
        usage(opts.invoke)
        {:error, "Invalid arguments"}
    end
  end
  defp run_in_root(root, pr_ref, opts) do
    with_optional_checkout(root, pr_ref, :run, opts, fn checkout_ctx ->
      with {:ok, fetch_ctx} <- run_fetch(root, pr_ref),
           {:ok, apply_ctx} <- run_apply(root, opts),
           {:ok, run_path} <- write_run_md(root, fetch_ctx) do
        fetch_ctx = Map.put(fetch_ctx, :checkout_ctx, checkout_ctx)

        case maybe_commit(root, apply_ctx.tasks_yaml, opts) do
          {:error, msg} ->
            {:error, msg}

          commit_ctx ->
            print_run_summary(root, fetch_ctx, apply_ctx, run_path, commit_ctx, opts)
            :ok
        end
      end
    end)
  end


  defp halt_on_error(:ok), do: :ok
  defp halt_on_error({:ok, _}), do: :ok

  defp halt_on_error({:error, msg}) when is_binary(msg) do
    IO.puts(:stderr, "ERROR: #{msg}")
    System.halt(1)
  end

  defp usage(invoke) do
    IO.puts(:stderr, """
    Usage:
      #{invoke} [-C PATH|--repo PATH] [global opts] fetch <pr-number|pr-url|owner/repo#number>
      #{invoke} [-C PATH|--repo PATH] [global opts] apply [--commit]
      #{invoke} [-C PATH|--repo PATH] [global opts] run <pr-number|pr-url|owner/repo#number> [--commit]
      #{invoke} [-C PATH|--repo PATH] [global opts] post <pr-number|pr-url>
      #{invoke} [-C PATH|--repo PATH] [global opts] config

    Global opts:
      -C, --repo PATH         Target git repo (defaults to current directory).
      --config PATH           Extra config file to load (repeatable).
      --verbose / --quiet     Stream full agent output to terminal (also saved in `.agent/codex_exec.log`).
      --model MODEL           Set the Codex model (same as `codex --model`).
      --reasoning-effort LVL  Set `reasoning_effort` via `codex --config` (e.g. low|medium|high).
      --codex-config key=val  Pass through `codex --config key=value` (repeatable).
      --commit                After a successful apply/run, create a local git commit (never pushes).

      --checkout / --no-checkout
                              When enabled, run `gh pr checkout` before the command.
                              Defaults: run=yes, fetch=no, post=no (override via config `checkout_default`).
      --stash / --no-stash     If checkout is enabled and the tree is dirty, allow auto-stash.
      --stash-message MSG      Stash message (default: "#{invoke} auto-stash").

      --worktree              (run only) Run inside a per-PR git worktree under `.worktrees/` (enables parallel PR sessions).
      --worktree-dir DIR      Override worktree base dir (default: `<repo_root>/.worktrees/agent_reviews`).

      --fallback-top-level     If JSON metadata is missing/invalid, allow posting a single top-level comment as fallback (discouraged).

    Config files (optional):
      - ~/.agent_reviews.toml
      - <repo_root>/.agent_reviews.toml

    Env (optional):
      - AGENT_CMD (or CODEX_CMD)   Agent executable (default: codex)
      - AGENT_ARGS (or CODEX_ARGS) Extra args passed to the agent (shellwords)

    Notes:
      - `run` does fetch -> apply -> writes `.agent/run.md` (does not post).
      - `post` is optional and posts per-thread replies when the required JSON metadata block is present.
    """)
  end

  defp git_root(nil), do: git_root(".")

  defp git_root(path) do
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

  defp git_common_root(root) do
    case System.cmd("git", ["rev-parse", "--git-common-dir"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        p = String.trim(out)
        p = if Path.type(p) == :absolute, do: p, else: Path.join(root, p)
        {:ok, Path.dirname(p)}

      {out, _} ->
        {:error, "Failed to determine git common dir.\n\nOutput:\n#{out}"}
    end
  end


  defp invoke_name do
    System.get_env("CODEX_REVIEWS_INVOKE") || "agent_reviews"
  end

  defp ensure_cmd(cmd) do
    if System.find_executable(cmd), do: :ok, else: {:error, "Missing dependency: '#{cmd}' (expected on PATH)"}
  end


  # ----- Config loading (minimal TOML subset) -----

  defp load_effective_opts(root, opts) do
    defaults = %{
      agent_cmd: "codex",
      agent_args: "",
      model: nil,
      reasoning_effort: nil,
      full_auto: true,
      skip_nitpicks: false,
      auto_commit: false,
      verbose: false,
      checkout_default: nil
    }

    user_cfg_path = Path.join(System.user_home!(), ".agent_reviews.toml")
    repo_cfg_path = Path.join(root, ".agent_reviews.toml")

    with {:ok, user_cfg} <- read_optional_config(user_cfg_path),
         {:ok, repo_cfg} <- read_optional_config(repo_cfg_path),
         {:ok, extra_cfg} <- read_many_optional_configs(Map.get(opts, :config_paths, [])) do
      cfg =
        defaults
        |> Map.merge(user_cfg)
        |> Map.merge(repo_cfg)
        |> Map.merge(extra_cfg)
        |> apply_env_overrides()

      {:ok, apply_config_to_opts(opts, cfg)}
    end
  end

  defp apply_env_overrides(cfg) do
    agent_cmd = System.get_env("AGENT_CMD") || System.get_env("CODEX_CMD")
    agent_args = System.get_env("AGENT_ARGS") || System.get_env("CODEX_ARGS")

    cfg
    |> maybe_put_string(:agent_cmd, agent_cmd)
    |> maybe_put_string(:agent_args, agent_args)
  end

  defp maybe_put_string(map, _k, nil), do: map

  defp maybe_put_string(map, k, v) do
    v = String.trim(to_string(v))
    if v == "", do: map, else: Map.put(map, k, v)
  end

  defp read_many_optional_configs(paths) when is_list(paths) do
    Enum.reduce_while(paths, {:ok, %{}}, fn path, {:ok, acc} ->
      case read_optional_config(path) do
        {:ok, cfg} -> {:cont, {:ok, Map.merge(acc, cfg)}}
        {:error, msg} -> {:halt, {:error, msg}}
      end
    end)
  end

  defp read_optional_config(nil), do: {:ok, %{}}

  defp read_optional_config(path) do
    path = Path.expand(to_string(path))

    if File.exists?(path) do
      with {:ok, content} <- File.read(path),
           {:ok, cfg} <- parse_simple_toml(path, content) do
        {:ok, cfg}
      else
        {:error, msg} -> {:error, msg}
        _ -> {:error, "Failed to read config: #{path}"}
      end
    else
      {:ok, %{}}
    end
  end

  defp parse_simple_toml(path, content) when is_binary(content) do
    lines = String.split(content, "
", trim: false)

    Enum.reduce_while(Enum.with_index(lines, 1), {:ok, %{}}, fn {line, line_no}, {:ok, acc} ->
      trimmed = String.trim(line)

      cond do
        trimmed == "" ->
          {:cont, {:ok, acc}}

        String.starts_with?(trimmed, "#") ->
          {:cont, {:ok, acc}}

        true ->
          case parse_toml_kv(trimmed) do
            {:ok, {k, v}} ->
              case normalize_config_kv(k, v) do
                {:ok, {key, value}} -> {:cont, {:ok, Map.put(acc, key, value)}}
                :ignore -> {:cont, {:ok, acc}}
                {:error, msg} -> {:halt, {:error, "#{path}:#{line_no}: #{msg}"}}
              end

            {:error, msg} ->
              {:halt, {:error, "#{path}:#{line_no}: #{msg}"}}
          end
      end
    end)
  end

  defp parse_toml_kv(line) do
    case String.split(line, "=", parts: 2) do
      [k, v] -> {:ok, {String.trim(k), String.trim(v)}}
      _ -> {:error, "Expected `key = value`"}
    end
  end

  defp normalize_config_kv(key, raw) do
    key = key |> String.trim() |> String.downcase()

    with {:ok, value} <- parse_toml_value(raw) do
      case key do
        "agent_cmd" -> {:ok, {:agent_cmd, to_string(value)}}
        "agent_args" -> {:ok, {:agent_args, to_string(value)}}
        "model" -> {:ok, {:model, to_string(value)}}
        "reasoning_effort" -> {:ok, {:reasoning_effort, to_string(value)}}
        "full_auto" when is_boolean(value) -> {:ok, {:full_auto, value}}
        "skip_nitpicks" when is_boolean(value) -> {:ok, {:skip_nitpicks, value}}
        "auto_commit" when is_boolean(value) -> {:ok, {:auto_commit, value}}
        "verbose" when is_boolean(value) -> {:ok, {:verbose, value}}
        "checkout_default" when is_boolean(value) -> {:ok, {:checkout_default, value}}
        _ -> :ignore
      end
    end
  end

  defp parse_toml_value(raw) do
    raw = String.trim(raw)

    cond do
      raw in ["true", "false"] ->
        {:ok, raw == "true"}

      Regex.match?(~r/^-?\d+$/, raw) ->
        case Integer.parse(raw) do
          {n, ""} -> {:ok, n}
          _ -> {:error, "Invalid integer"}
        end

      String.starts_with?(raw, "\"") ->
        parse_toml_string(raw)

      true ->
        {:error, "Strings must be quoted (e.g. key = \"value\")"}
    end
  end

  defp parse_toml_string(raw) do
    raw = String.trim(raw)

    if String.length(raw) >= 2 and String.starts_with?(raw, "\"") and String.ends_with?(raw, "\"") do
      inner = String.slice(raw, 1, String.length(raw) - 2)
      {:ok, toml_unescape(inner)}
    else
      {:error, "Unterminated string"}
    end
  end

  defp toml_unescape(s) do
    s
    |> String.replace("\\\\", "\\")
    |> String.replace("\\\"", "\"")
  end

  defp apply_config_to_opts(opts, cfg) do
    opts = Map.put(opts, :full_auto, Map.get(cfg, :full_auto, true))
    opts = Map.put(opts, :skip_nitpicks, Map.get(cfg, :skip_nitpicks, false))

    checkout_default = Map.get(cfg, :checkout_default, nil)
    opts = if is_boolean(checkout_default), do: Map.put(opts, :checkout_default, checkout_default), else: opts

    opts = Map.put(opts, :agent_cmd, Map.get(cfg, :agent_cmd, "codex"))
    opts = Map.put(opts, :agent_args, Map.get(cfg, :agent_args, ""))

    opts = if is_nil(Map.get(opts, :model)), do: Map.put(opts, :model, Map.get(cfg, :model, nil)), else: opts

    opts =
      if is_nil(Map.get(opts, :reasoning_effort)),
        do: Map.put(opts, :reasoning_effort, Map.get(cfg, :reasoning_effort, nil)),
        else: opts

    opts =
      if Map.get(opts, :verbose_overridden?, false),
        do: opts,
        else: Map.put(opts, :verbose?, Map.get(cfg, :verbose, false))

    opts =
      if Map.get(opts, :commit_overridden?, false),
        do: opts,
        else: Map.put(opts, :commit?, Map.get(cfg, :auto_commit, false) == true)

    opts
  end

  defp effective_config_summary(opts, checkout?) do
    agent = Map.get(opts, :agent_cmd, "codex")
    agent_args = Map.get(opts, :agent_args, "")
    model = Map.get(opts, :model, nil) || "(default)"
    reasoning = Map.get(opts, :reasoning_effort, nil) || "(default)"
    full_auto = Map.get(opts, :full_auto, true)
    skip_nitpicks = Map.get(opts, :skip_nitpicks, false)

    checkout_str =
      cond do
        is_boolean(checkout?) -> to_string(checkout?)
        true -> "(default)"
      end

    args_str = if String.trim(to_string(agent_args)) == "", do: "(none)", else: to_string(agent_args)

    "agent_cmd=#{agent}, agent_args=#{args_str}, model=#{model}, reasoning=#{reasoning}, full_auto=#{full_auto}, skip_nitpicks=#{skip_nitpicks}, checkout=#{checkout_str}"
  end


  defp ensure_repo_local_exclude(root) do
    case repo_local_exclude_path(root) do
      {:ok, exclude_path} ->
        content =
          case File.read(exclude_path) do
            {:ok, s} -> s
            _ -> ""
          end

        needs_agent? = not Regex.match?(~r/^\s*\.agent\/\s*$/m, content)
        needs_worktrees? = not Regex.match?(~r/^\s*\.worktrees\/\s*$/m, content)

        if not (needs_agent? or needs_worktrees?) do
          :ok
        else
          File.mkdir_p!(Path.dirname(exclude_path))

          lines =
            [
              if(String.trim(content) == "", do: "", else: "
"),
              "# agent_reviews (local-only)
",
              if(needs_agent?, do: ".agent/
", else: ""),
              if(needs_worktrees?, do: ".worktrees/
", else: "")
            ]
            |> IO.iodata_to_binary()

          File.write!(exclude_path, content <> lines)

          added =
            []
            |> then(fn acc -> if(needs_agent?, do: [".agent/" | acc], else: acc) end)
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
            " Add them manually by appending `.agent/` and `.worktrees/` to #{p}."

          true ->
            " Add them manually by appending `.agent/` and `.worktrees/` to `.git/info/exclude`."
        end

      IO.puts(:stderr, "WARN: Could not write repo-local exclude (#{inspect(r)})." <> hint)
      :ok

    e ->
      IO.puts(:stderr, "WARN: Failed to update repo-local exclude: #{Exception.message(e)}")
      :ok
  end

  defp repo_local_exclude_path(root) do
    case System.cmd("git", ["rev-parse", "--git-path", "info/exclude"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        p = String.trim(out)
        p = if Path.type(p) == :absolute, do: p, else: Path.join(root, p)
        {:ok, p}

      _ ->
        {:error, :no_git}
    end
  end


  defp ensure_gh_authed do
    with :ok <- ensure_cmd("gh") do
      case System.cmd("gh", ["auth", "status", "-h", "github.com"], stderr_to_stdout: true) do
        {_out, 0} -> :ok
        {out, _} -> {:error, "GitHub CLI not authenticated. Run: gh auth login\n\nOutput:\n#{out}"}
      end
    end
  end


  # ----- Optional PR checkout (gh pr checkout) + auto-stash -----

  defp checkout_enabled?(command, opts) do
    case Map.get(opts, :checkout, :unset) do
      v when is_boolean(v) ->
        v

      _ ->
        command_default =
          case command do
            :run -> true
            :fetch -> false
            :post -> false
            _ -> false
          end

        cfg_default = Map.get(opts, :checkout_default, nil)
        if is_boolean(cfg_default), do: cfg_default, else: command_default
    end
  end

  defp with_optional_checkout(root, pr_ref, command, opts, fun) when is_function(fun, 1) do
    if checkout_enabled?(command, opts) do
      with {:ok, checkout_ctx} <- checkout_pr_branch(root, pr_ref, opts) do
        try do
          fun.(checkout_ctx)
        after
          _ = maybe_reapply_stash(root, checkout_ctx)
        end
      end
    else
      fun.(%{checked_out?: false, stash_ref: nil})
    end
  end

  defp checkout_pr_branch(root, pr_ref, opts) do
    with :ok <- ensure_gh_authed(),
         {:ok, {_owner, _repo, number}} <- parse_pr_ref(pr_ref, root),
         {:ok, stash_ref} <- maybe_stash_before_checkout(root, opts),
         {:ok, head_sha} <- gh_pr_head_sha(root, number),
         :ok <- gh_pr_checkout(root, number),
         :ok <- ensure_contains_pr_head_commit(root, "", head_sha),
         {:ok, branch} <- current_branch(root) do
      IO.puts(:stderr, "INFO: Checked out PR #{number} branch: #{branch}")

      if stash_ref do
        IO.puts(:stderr, "INFO: Stashed changes as #{stash_ref}; will try to re-apply after completion")
      end

      {:ok, %{checked_out?: true, pr_number: number, branch: branch, head_sha: head_sha, stash_ref: stash_ref}}
    end
  end

  defp maybe_stash_before_checkout(root, opts) do
    if working_tree_clean?(root) do
      {:ok, nil}
    else
      pref = Map.get(opts, :stash, :unset)

      cond do
        pref == true ->
          do_stash(root, opts)

        pref == false ->
          {:error,
           "Working tree has local changes; refusing to checkout PR branch.\n\n" <>
             "Clean the tree, or re-run with --stash to auto-stash changes."}

        stdin_tty?() and prompt_yes_no("Working tree has changes. Stash them to checkout PR branch? [Y/n] ") ->
          do_stash(root, opts)

        stdin_tty?() ->
          {:error,
           "Working tree has local changes; refusing to checkout PR branch.\n\n" <>
             "Hint: stash/commit/reset your changes, or re-run with --stash."}

        true ->
          {:error,
           "Working tree has local changes, but this command is running non-interactively.\n\n" <>
             "Re-run with --stash, or clean the tree before running."}
      end
    end
  end

  defp do_stash(root, opts) do
    msg = Map.get(opts, :stash_message) || "#{invoke_name()} auto-stash"

    {out, status} = System.cmd("git", ["stash", "push", "-u", "-m", msg], cd: root, stderr_to_stdout: true)

    if status != 0 do
      {:error, "Failed to stash local changes.\n\nOutput:\n#{out}"}
    else
      {ref_out, ref_status} = System.cmd("git", ["stash", "list", "-1", "--format=%gd"], cd: root, stderr_to_stdout: true)
      ref = String.trim(ref_out)

      if ref_status == 0 and ref != "" do
        {:ok, ref}
      else
        {:ok, "stash@{0}"}
      end
    end
  end

  defp maybe_reapply_stash(_root, %{stash_ref: nil}), do: :ok
  defp maybe_reapply_stash(_root, %{stash_ref: ""}), do: :ok

  defp maybe_reapply_stash(root, %{stash_ref: stash_ref}) when is_binary(stash_ref) do
    {out, status} = System.cmd("git", ["stash", "apply", stash_ref], cd: root, stderr_to_stdout: true)

    if status == 0 do
      IO.puts(:stderr, "INFO: Re-applied stash successfully (#{stash_ref})")
      :ok
    else
      IO.puts(:stderr, "WARN: Failed to re-apply stash (#{stash_ref}). The stash was NOT dropped.")
      IO.puts(:stderr, "WARN: Resolve manually with: git stash list; git stash apply #{stash_ref}")
      IO.puts(:stderr, "WARN: Output:\n#{out}")
      :ok
    end
  end

  defp working_tree_clean?(root) do
    case System.cmd("git", ["status", "--porcelain"], cd: root, stderr_to_stdout: true) do
      {out, 0} -> String.trim(out) == ""
      _ -> false
    end
  end

  defp stdin_tty? do
    case System.cmd("sh", ["-c", "test -t 0"], stderr_to_stdout: true) do
      {_out, 0} -> true
      _ -> false
    end
  end

  defp prompt_yes_no(prompt) when is_binary(prompt) do
    answer = IO.gets(prompt)

    case answer do
      nil -> false
      s ->
        s = s |> String.trim() |> String.downcase()
        s in ["", "y", "yes"]
    end
  end

  defp current_branch(root) do
    case System.cmd("git", ["rev-parse", "--abbrev-ref", "HEAD"], cd: root, stderr_to_stdout: true) do
      {out, 0} -> {:ok, String.trim(out)}
      {out, _} -> {:error, "Failed to determine current git branch.\n\nOutput:\n#{out}"}
    end
  end

  defp gh_pr_head_sha(root, number) do
    {out, status} =
      System.cmd("gh", ["pr", "view", Integer.to_string(number), "--json", "headRefOid"], cd: root, stderr_to_stdout: true)

    if status != 0 do
      {:error, "Failed to query PR head SHA via gh.\n\nOutput:\n#{out}"}
    else
      with {:ok, decoded} <- Json.parse(out),
           oid when is_binary(oid) <- Map.get(decoded, "headRefOid") do
        {:ok, oid}
      else
        _ -> {:error, "Malformed gh pr view JSON while reading headRefOid."}
      end
    end
  end

  defp gh_pr_checkout(root, number) do
    {out, status} = System.cmd("gh", ["pr", "checkout", Integer.to_string(number)], cd: root, stderr_to_stdout: true)

    if status == 0 do
      :ok
    else
      {:error, "Failed to checkout PR via gh.\n\nOutput:\n#{out}"}
    end
  end


  # ----- Worktrees (optional) -----

  defp ensure_pr_worktree_root(root, pr_ref, opts) do
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
          Path.join([common_root, ".worktrees", invoke_name()])

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

      {out, status} = System.cmd("git", ["worktree", "add", wt_root], cd: common_root, stderr_to_stdout: true)

      if status == 0 do
        IO.puts(:stderr, "INFO: Created worktree: #{wt_root}")
        :ok
      else
        {:error, "Failed to create worktree at #{wt_root}.

Output:
#{out}"}
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
        {:error, "Path exists but is not a git worktree: #{wt_root}

Output:
#{out}"}
    end
  end

  defp print_config_summary(root, opts) do
    user_cfg = Path.join(System.user_home!(), ".agent_reviews.toml")
    repo_cfg = Path.join(root, ".agent_reviews.toml")

    IO.puts("\n== #{opts.invoke} config ==")
    IO.puts("Repo: #{root}")
    IO.puts("Config files (loaded if present):")
    IO.puts("  - #{user_cfg}")
    IO.puts("  - #{repo_cfg}")

    extra = Map.get(opts, :config_paths, [])

    if extra != [] do
      IO.puts("Extra --config files:")
      Enum.each(extra, fn p -> IO.puts("  - #{Path.expand(to_string(p))}") end)
    end

    IO.puts("Effective: #{effective_config_summary(opts, Map.get(opts, :checkout_default, nil))}")
    IO.puts("Status: ✅")
  end

  defp run_fetch(root, pr_ref) do
    with :ok <- ensure_gh_authed(),
         {:ok, {owner, repo, number}} <- parse_pr_ref(pr_ref, root),
         :ok <- File.mkdir_p(Path.join(root, @agent_dir)) do
      agent_dir = Path.join(root, @agent_dir)
      review_threads_path = Path.join(agent_dir, "review_threads.json")
      tasks_yaml_path = Path.join(agent_dir, "tasks.yaml")
      tasks_md_path = Path.join(agent_dir, "tasks.md")

      case gh_graphql_pages(owner, repo, number) do
        {:ok,
         %{
           pr_title: pr_title,
           pr_url: pr_url,
           head_ref: head_ref,
           base_ref: base_ref,
           head_sha: head_sha,
           base_sha: base_sha,
           truncated?: truncated?,
           tasks: tasks,
           raw_pages: raw_pages
         }} ->
          File.write!(review_threads_path, raw_pages)
          File.write!(tasks_yaml_path, tasks_yaml(pr_title, pr_url, head_ref, base_ref, head_sha, base_sha, tasks))
          File.write!(tasks_md_path, tasks_md(pr_title, pr_url, tasks))

          if truncated? do
            IO.puts(
              :stderr,
              "WARN: reviewThreads truncated (max_pages=#{max_pages()}, page_size=100 → max_threads=#{max_pages() * 100}). Set CODEX_REVIEWS_MAX_PAGES to increase."
            )
          end

          IO.puts("Wrote: #{tasks_yaml_path}")
          IO.puts("Wrote: #{tasks_md_path}")
          IO.puts("Wrote: #{review_threads_path}")

          {:ok,
           %{
             pr_title: pr_title,
             pr_url: pr_url,
             head_ref: head_ref,
             base_ref: base_ref,
             head_sha: head_sha,
             base_sha: base_sha,
             truncated?: truncated?,
             tasks: tasks
           }}

        {:error, msg, raw_pages} ->
          File.write!(review_threads_path, raw_pages)
          IO.puts("Wrote: #{review_threads_path}")
          {:error, msg}

        {:error, msg} ->
          {:error, msg}
      end
    end
  end

  defp run_apply(root, opts) do
    agent_dir = Path.join(root, @agent_dir)
    tasks_yaml = Path.join(agent_dir, "tasks.yaml")

    unless File.exists?(tasks_yaml) do
      {:error, "Missing #{tasks_yaml} (run: #{opts.invoke} fetch <pr>)"}
    else
      prompt_md = Path.join(agent_dir, "codex_prompt.md")
      responses_raw_md = Path.join(agent_dir, "review_responses.raw.md")
      responses_md = Path.join(agent_dir, "review_responses.md")
      exec_log = Path.join(agent_dir, "codex_exec.log")
      patch_path = Path.join(agent_dir, "changes.patch")

      File.mkdir_p!(agent_dir)

      agent_cmd_in = Map.get(opts, :agent_cmd, "codex")
      agent_args = shellwords(Map.get(opts, :agent_args, "")) ++ codex_args_from_opts(opts)
      agent_args = maybe_add_full_auto(agent_args, Map.get(opts, :full_auto, true))

      with :ok <- ensure_clean_working_tree(root),
           :ok <- ensure_on_recorded_pr_head(root, tasks_yaml),
           {:ok, agent_cmd} <- resolve_agent_cmd(agent_cmd_in),
           :ok <- ensure_agent_noninteractive(agent_cmd) do
        if agent_cmd != agent_cmd_in do
          IO.puts(:stderr, "INFO: Using agent executable at #{agent_cmd}")
        end

        File.write!(prompt_md, agent_prompt_template(opts))
        IO.puts("Wrote: #{prompt_md}")

        case run_agent(root, agent_cmd, agent_args, prompt_md, responses_raw_md, exec_log, opts) do
          :ok ->
            wrap_review_responses!(root, tasks_yaml, responses_raw_md, responses_md, exec_log)
            write_changes_patch!(root, patch_path)

            {:ok,
             %{
               tasks_yaml: tasks_yaml,
               prompt_md: prompt_md,
               responses_raw_md: responses_raw_md,
               responses_md: responses_md,
               exec_log: exec_log,
               patch_path: patch_path,
               changed_files: changed_files(root),
               posting_metadata: detect_posting_metadata(root, responses_md)
             }}

          other ->
            other
        end
      else
        {:error, msg} -> {:error, msg}
      end
    end
  end

  defp run_agent(root, agent_cmd, agent_args, prompt_md, responses_md, exec_log, opts) do
    label = "Running Codex (logs: #{exec_log})"

    status =
      if opts.verbose? do
        IO.puts("#{label}...")

        # Stream to terminal and also save to exec_log.
        bash_args =
          [
            "-c",
            ~S(set -o pipefail; cat "$1" | "$2" exec -C "$3" --output-last-message "$4" "${@:6}" - 2>&1 | tee "$5"),
            "_",
            prompt_md,
            agent_cmd,
            root,
            responses_md,
            exec_log
          ] ++ agent_args

        {_stream, status} = System.cmd("bash", bash_args, cd: root, into: IO.stream(:stdio, :line))
        status
      else
        # Quiet mode: save full output to exec_log only and show a lightweight spinner while Codex runs.
        bash_args =
          [
            "-c",
            ~S(set -o pipefail; cat "$1" | "$2" exec -C "$3" --output-last-message "$4" "${@:6}" - >"$5" 2>&1),
            "_",
            prompt_md,
            agent_cmd,
            root,
            responses_md,
            exec_log
          ] ++ agent_args

        {_out, status} =
          run_with_spinner(label, fn ->
            System.cmd("bash", bash_args, cd: root, stderr_to_stdout: true)
          end)

        status
      end

    IO.puts("Wrote: #{responses_md}")

    if status != 0 do
      ensure_failure_details!(responses_md, exec_log)
      hint = codex_failure_hint(exec_log)
      {:error, "Codex CLI exited with status #{status} (see #{responses_md}).#{hint}"}
    else
      :ok
    end
  end

  defp run_with_spinner(label, fun) when is_function(fun, 0) do
    if spinner_enabled?() do
      frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
      task = Task.async(fun)

      result = await_with_spinner(task, label, frames, 0)
      IO.write("\r#{label}... done\n")
      result
    else
      IO.puts("#{label}...")
      fun.()
    end
  end

  defp await_with_spinner(task, label, frames, idx) do
    case Task.yield(task, 120) do
      {:ok, result} ->
        result

      nil ->
        frame = Enum.at(frames, rem(idx, length(frames)))
        IO.write("\r#{label}... #{frame}")
        await_with_spinner(task, label, frames, idx + 1)
    end
  end

  defp spinner_enabled? do
    IO.ANSI.enabled?() and System.get_env("TERM", "dumb") != "dumb"
  end

  defp codex_args_from_opts(opts) when is_map(opts) do
    model_args =
      case Map.get(opts, :model) do
        m when is_binary(m) and m != "" -> ["--model", m]
        _ -> []
      end

    reasoning_args =
      case Map.get(opts, :reasoning_effort) do
        r when is_binary(r) and r != "" ->
          ["--config", ~s(reasoning_effort=#{toml_string(r)})]

        _ ->
          []
      end

    config_args =
      opts
      |> Map.get(:codex_config, [])
      |> Enum.flat_map(fn kv -> ["--config", kv] end)

    model_args ++ reasoning_args ++ config_args
  end

  defp toml_string(value) do
    escaped =
      value
      |> to_string()
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")

    ~s("#{escaped}")
  end

  defp print_fetch_summary(root, fetch_ctx, opts) do
    agent_dir = Path.join(root, @agent_dir)

    tasks_yaml = display_output_path(Path.join(agent_dir, "tasks.yaml"), root)
    tasks_md = display_output_path(Path.join(agent_dir, "tasks.md"), root)
    threads = display_output_path(Path.join(agent_dir, "review_threads.json"), root)
    invoke = invoke_for_root(opts.invoke, root)

    IO.puts("\n== #{opts.invoke} fetch ==")
    IO.puts("Repo: #{Path.expand(root)}")
    IO.puts("PR: #{fetch_ctx.pr_url}")
    IO.puts("Title: #{fetch_ctx.pr_title}")
    IO.puts("Effective: #{effective_config_summary(opts, checkout_enabled?(:fetch, opts))}")
    IO.puts("Tasks: #{format_type_counts(fetch_ctx.tasks)}")
    IO.puts("Outputs:")
    IO.puts("  - `#{tasks_yaml}`")
    IO.puts("  - `#{tasks_md}`")
    IO.puts("  - `#{threads}`")
    IO.puts("Next: `#{invoke} apply` or `#{invoke} run #{fetch_ctx.pr_url}`")
    IO.puts("Status: ✅ success")
  end

  defp print_apply_summary(root, apply_ctx, commit_ctx, opts) do
    responses = display_output_path(apply_ctx.responses_md, root)
    exec_log = display_output_path(apply_ctx.exec_log, root)
    patch = display_output_path(apply_ctx.patch_path, root)
    invoke = invoke_for_root(opts.invoke, root)

    IO.puts("\n== #{opts.invoke} apply ==")
    IO.puts("Repo: #{Path.expand(root)}")
    IO.puts("Effective: #{effective_config_summary(opts, false)}")
    IO.puts("Outputs:")
    IO.puts("  - `#{responses}`")
    IO.puts("  - `#{exec_log}`")
    IO.puts("  - `#{patch}`")
    IO.puts("Changed files: #{format_changed_files(apply_ctx.changed_files)}")
    IO.puts("Posting metadata: #{format_posting_metadata(apply_ctx.posting_metadata)}")
    IO.puts("Commit: #{format_commit(commit_ctx)}")
    IO.puts("Next: review `#{patch}`, then `#{invoke} post <pr-number|pr-url>` (optional)")
    IO.puts("Status: ✅ success")
  end

  defp print_run_summary(root, fetch_ctx, apply_ctx, run_path, commit_ctx, opts) do
    run_rel = display_output_path(run_path, root)
    patch = display_output_path(apply_ctx.patch_path, root)
    responses = display_output_path(apply_ctx.responses_md, root)
    invoke = invoke_for_root(opts.invoke, root)

    IO.puts("\n== #{opts.invoke} run ==")
    IO.puts("Repo: #{Path.expand(root)}")
    IO.puts("PR: #{fetch_ctx.pr_url}")
    IO.puts("Title: #{fetch_ctx.pr_title}")
    IO.puts("Effective: #{effective_config_summary(opts, checkout_enabled?(:run, opts))}")
    IO.puts("Tasks: #{format_type_counts(fetch_ctx.tasks)}")
    IO.puts("Outputs:")
    IO.puts("  - `#{responses}`")
    IO.puts("  - `#{run_rel}`")
    IO.puts("  - `#{patch}`")
    IO.puts("Changed files: #{format_changed_files(apply_ctx.changed_files)}")
    IO.puts("Posting metadata: #{format_posting_metadata(apply_ctx.posting_metadata)}")
    IO.puts("Commit: #{format_commit(commit_ctx)}")
    IO.puts("Next: `#{invoke} post #{fetch_ctx.pr_url}` (optional)")
    IO.puts("Status: ✅ success")
  end

  defp print_post_summary(root, pr_ref, post_ctx, opts) do
    invoke = invoke_for_root(opts.invoke, root)

    IO.puts("\n== #{opts.invoke} post ==")
    IO.puts("Repo: #{Path.expand(root)}")
    IO.puts("PR: #{pr_ref}")
    IO.puts("Effective: #{effective_config_summary(opts, checkout_enabled?(:post, opts))}")
    IO.puts("Thread replies posted: #{post_ctx.posted_replies}")
    IO.puts("Top-level comment posted: #{if(post_ctx.top_level_posted?, do: "yes", else: "no")}")
    IO.puts("Next: `#{invoke} run <pr-number|pr-url>` (optional)")
    IO.puts("Status: ✅ success")
  end

  defp display_output_path(path, root) do
    abs_path = Path.expand(path)
    root_abs = Path.expand(root)
    cwd = Path.expand(File.cwd!())

    cond do
      abs_path == cwd ->
        "."

      String.starts_with?(abs_path, cwd <> "/") ->
        Path.relative_to(abs_path, cwd)

      cwd == root_abs ->
        Path.relative_to(abs_path, root_abs)

      String.starts_with?(abs_path, root_abs <> "/") ->
        Path.relative_to(abs_path, root_abs)

      true ->
        abs_path
    end
  end

  defp invoke_for_root(invoke, root) do
    root_abs = Path.expand(root)
    cwd = Path.expand(File.cwd!())

    if cwd == root_abs do
      invoke
    else
      root_arg =
        if root_abs == cwd do
          "."
        else
          if String.starts_with?(root_abs, cwd <> "/") do
            Path.relative_to(root_abs, cwd)
          else
            root_abs
          end
        end

      "#{invoke} -C #{shell_quote(root_arg)}"
    end
  end

  defp shell_quote(value) do
    escaped =
      value
      |> to_string()
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")

    ~s("#{escaped}")
  end

  defp format_type_counts(tasks) do
    freqs =
      tasks
      |> Enum.map(& &1.type)
      |> Enum.frequencies()

    total = length(tasks)

    parts =
      freqs
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {k, v} -> "#{k}=#{v}" end)
      |> Enum.join(", ")

    if parts == "" do
      "#{total}"
    else
      "#{total} (#{parts})"
    end
  end

  defp format_changed_files([]), do: "0"

  defp format_changed_files(files) when is_list(files) do
    count = length(files)

    list =
      case files do
        xs when length(xs) <= 8 -> Enum.join(xs, ", ")
        xs -> Enum.join(Enum.take(xs, 8), ", ") <> ", …"
      end

    "#{count} (#{list})"
  end

  defp format_posting_metadata(%{status: :missing}), do: "missing"

  defp format_posting_metadata(%{status: :invalid, reason: reason}),
    do: "invalid (#{reason})"

  defp format_posting_metadata(%{status: :ok, replies: replies, top_level?: top_level?}) do
    "ok (replies=#{replies}, top_level_comment=#{if(top_level?, do: "yes", else: "no")})"
  end

  defp format_posting_metadata(_), do: "unknown"

  defp format_commit(%{enabled?: false}), do: "disabled"
  defp format_commit(%{enabled?: true, committed?: false, reason: :no_changes}), do: "enabled (no changes)"
  defp format_commit(%{enabled?: true, committed?: true, sha: sha}), do: "committed (#{sha})"
  defp format_commit(_), do: "unknown"

  defp resolve_agent_cmd(cmd) when is_binary(cmd) do
    cmd = String.trim(cmd)

    case System.find_executable(cmd) do
      nil ->
        {:error, "Codex CLI not found ('#{cmd}'). Install Codex CLI and/or set AGENT_CMD/CODEX_CMD to the correct executable."}

      path ->
        # If this looks like an asdf shim and is failing with "No preset version", try to find a non-shim codex.
        {out, status} = System.cmd(path, ["--help"], stderr_to_stdout: true)

        if status != 0 and String.contains?(out, "No preset version installed for command codex") do
          case find_non_asdf_codex() do
            {:ok, other} ->
              {:ok, other}

            :error ->
              {:error,
               "Your shell is resolving `codex` to an asdf shim, but it isn't runnable here.\nRun `which codex` and either install Codex CLI properly or set `CODEX_CMD` to the real Codex executable path.\n\nOutput:\n#{out}"}
          end
        else
          {:ok, cmd}
        end
    end
  end

  defp find_non_asdf_codex do
    candidates =
      [
        "/opt/homebrew/bin/codex",
        "/usr/local/bin/codex",
        "/usr/bin/codex"
      ] ++ path_candidates()

    Enum.find_value(candidates, :error, fn path ->
      if File.regular?(path) and File.exists?(path) do
        {out, status} = System.cmd(path, ["--help"], stderr_to_stdout: true)
        if status == 0 and String.contains?(out, "Codex CLI"), do: {:ok, path}, else: nil
      end
    end)
  end

  defp path_candidates do
    System.get_env("PATH", "")
    |> String.split(":", trim: true)
    |> Enum.reject(&String.contains?(&1, ".asdf/shims"))
    |> Enum.map(&Path.join(&1, "codex"))
  end

  defp ensure_failure_details!(responses_md, exec_log) do
    responses_empty? =
      case File.read(responses_md) do
        {:ok, content} -> String.trim(content) == ""
        _ -> true
      end

    if responses_empty? and File.exists?(exec_log) do
      File.cp!(exec_log, responses_md)
    end
  end

  defp codex_failure_hint(exec_log) do
    case File.read(exec_log) do
      {:ok, log} ->
        cond do
          String.contains?(log, "stdin is not a terminal") ->
            "\nHint: your Codex invocation is running in interactive mode; ensure `codex exec` is available and being used."

          String.contains?(log, "Codex cannot access session files") or
              String.contains?(log, "permission denied") and String.contains?(log, ".codex/sessions") ->
            "\nHint: Codex cannot write to `~/.codex/sessions`. Fix ownership/permissions of `~/.codex` (Codex often suggests: `sudo chown -R $(whoami) ~/.codex`)."

          true ->
            ""
        end

      _ ->
        ""
    end
  end

  defp maybe_add_full_auto(args, full_auto?) when is_list(args) do
    if full_auto? != true do
      args
    else
      has_policy? =
        Enum.any?(args, fn
          "--full-auto" -> true
          "--dangerously-bypass-approvals-and-sandbox" -> true
          "--sandbox" -> true
          "-s" -> true
          "--ask-for-approval" -> true
          "-a" -> true
          _ -> false
        end)

      if has_policy?, do: args, else: ["--full-auto" | args]
    end
  end

  defp run_post(root, pr_ref, opts) do
    with :ok <- ensure_gh_authed(),
         :ok <- ensure_cmd("gh") do
      responses = Path.join([root, @agent_dir, "review_responses.md"])
      tasks_yaml = Path.join([root, @agent_dir, "tasks.yaml"])

      cond do
        not File.exists?(responses) ->
          {:error, "Missing #{responses} (run: #{opts.invoke} apply)"}

        not File.exists?(tasks_yaml) ->
          {:error, "Missing #{tasks_yaml} (run: #{opts.invoke} fetch <pr>)"}

        File.read!(responses) |> String.trim() == "" ->
          {:error, "#{responses} is empty"}

        true ->
          content = File.read!(responses)

          case extract_posting_metadata(content, root) do
            {:ok, %{"replies" => replies, "top_level_comment" => top_level_comment}} ->
              with {:ok, task_map} <- parse_tasks_yaml_for_posting(tasks_yaml) do
                replies_result = post_thread_replies(root, replies, task_map)
                top_level_result = maybe_post_top_level_comment(root, pr_ref, top_level_comment)

                case {replies_result, top_level_result} do
                  {{:ok, posted}, :ok} ->
                    {:ok,
                     %{
                       posted_replies: posted,
                       top_level_posted?: String.trim(to_string(top_level_comment)) != ""
                     }}

                  {{:error, msg}, :ok} ->
                    {:error, msg}

                  {{:ok, posted}, {:error, msg}} ->
                    {:error, "Posted #{posted} thread replies, but failed to post top-level comment.\n\n#{msg}"}

                  {{:error, msg1}, {:error, msg2}} ->
                    {:error, msg1 <> "\n\n" <> msg2}
                end
              else
                {:error, _} ->
                  {:error, "Failed to parse #{tasks_yaml} for posting validation."}
              end

            {:error, reason} ->
              if opts.post_fallback_top_level? do
                IO.puts(:stderr, "WARN: #{reason}; falling back to posting a single consolidated comment.")

                {out, status} =
                  System.cmd("gh", ["pr", "comment", pr_ref, "--body-file", responses], stderr_to_stdout: true)

                if status != 0 do
                  {:error, "Failed to post PR comment.\n\nOutput:\n#{out}"}
                else
                  {:ok, %{posted_replies: 0, top_level_posted?: true}}
                end
              else
                {:error,
                 "#{reason}\n\nRefusing to post a consolidated top-level comment by default.\nIf you really want that fallback, re-run with: #{opts.invoke} --fallback-top-level post #{pr_ref}"}
              end
          end
      end
    else
      {:error, msg} -> {:error, msg}
    end
  end

  defp gh_graphql_pages(owner, repo, number) do
    max_pages = max_pages()
    do_gh_graphql_pages(owner, repo, number, nil, 0, max_pages, [], nil, nil)
  end

  defp do_gh_graphql_pages(owner, repo, number, cursor, page_idx, max_pages, tasks_acc, raw_pages_acc, pr_meta)
       when page_idx < max_pages do
    query = graphql_query()

    args =
      [
        "api",
        "graphql",
        "-f",
        "query=#{query}",
        "-f",
        "owner=#{owner}",
        "-f",
        "repo=#{repo}",
        "-F",
        "number=#{number}"
      ] ++ if(is_binary(cursor) and cursor != "", do: ["-f", "after=#{cursor}"], else: [])

    case System.cmd("gh", args, stderr_to_stdout: true) do
      {out, 0} ->
        raw_pages_acc = (raw_pages_acc || []) ++ [String.trim(out)]

        with {:ok, decoded} <- Json.parse(out),
             {:ok, pr} <- fetch_in(decoded, ["data", "repository", "pullRequest"]),
             {:ok, threads} <- fetch_in(pr, ["reviewThreads"]),
             {:ok, page_info} <- fetch_in(threads, ["pageInfo"]) do
          has_next = Map.get(page_info, "hasNextPage", false) == true
          end_cursor = Map.get(page_info, "endCursor", "") || ""

          tasks =
            tasks_acc ++
              (threads
               |> Map.get("nodes", [])
               |> Enum.flat_map(&tasks_from_thread_node/1))

          pr_meta =
            pr_meta ||
              %{
                pr_title: Map.get(pr, "title", "") || "",
                pr_url: Map.get(pr, "url", "") || "",
                head_ref: Map.get(pr, "headRefName", "") || "",
                base_ref: Map.get(pr, "baseRefName", "") || "",
                head_sha: Map.get(pr, "headRefOid", "") || "",
                base_sha: Map.get(pr, "baseRefOid", "") || ""
              }

          cond do
            has_next and end_cursor != "" ->
              do_gh_graphql_pages(owner, repo, number, end_cursor, page_idx + 1, max_pages, tasks, raw_pages_acc, pr_meta)

            has_next and end_cursor == "" ->
              {:ok,
               Map.merge(pr_meta, %{
                 truncated?: true,
                 tasks:
                   tasks
                   |> sort_tasks()
                   |> Enum.with_index(1)
                   |> Enum.map(fn {t, id} -> Map.put(t, :id, id) end),
                 raw_pages: json_array(raw_pages_acc)
               })}

            true ->
              {:ok,
               Map.merge(pr_meta, %{
                 truncated?: false,
                 tasks:
                   tasks
                   |> sort_tasks()
                   |> Enum.with_index(1)
                   |> Enum.map(fn {t, id} -> Map.put(t, :id, id) end),
                 raw_pages: json_array(raw_pages_acc)
               })}
          end
        else
          _ ->
            {:error,
             "Malformed GitHub API response while extracting task fields (see .agent/review_threads.json for debugging).",
             json_array(raw_pages_acc)}
        end

      {out, _} ->
        {:error, "Failed to fetch PR review threads via GitHub API.\n\nOutput:\n#{out}", json_array(raw_pages_acc || [])}
    end
  end

  defp do_gh_graphql_pages(_owner, _repo, _number, _cursor, _page_idx, _max_pages, tasks_acc, raw_pages_acc, pr_meta) do
    pr_meta =
      pr_meta ||
        %{
          pr_title: "",
          pr_url: "",
          head_ref: "",
          base_ref: "",
          head_sha: "",
          base_sha: ""
        }

    {:ok,
     Map.merge(pr_meta, %{
       truncated?: true,
       tasks:
         tasks_acc
         |> sort_tasks()
         |> Enum.with_index(1)
         |> Enum.map(fn {t, id} -> Map.put(t, :id, id) end),
       raw_pages: json_array(raw_pages_acc || [])
     })}
  end

  defp graphql_query do
    """
    query($owner: String!, $repo: String!, $number: Int!, $after: String) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $number) {
          title
          url
          headRefName
          baseRefName
          headRefOid
          baseRefOid
          reviewThreads(first: 100, after: $after) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              id
              isResolved
              path
              line
              diffSide
              comments(last: 50) {
                totalCount
                nodes {
                  id
                  author { login }
                  body
                  createdAt
                }
              }
            }
          }
        }
      }
    }
    """
  end

  defp max_pages do
    case System.get_env("CODEX_REVIEWS_MAX_PAGES") do
      nil ->
        20

      raw ->
        case Integer.parse(String.trim(raw)) do
          {n, ""} when n > 0 -> n
          _ -> 20
        end
    end
  end

  defp fetch_in(map, keys) when is_map(map) and is_list(keys) do
    case get_in(map, keys) do
      nil -> {:error, :missing}
      value -> {:ok, value}
    end
  end

  defp tasks_from_thread_node(node) when is_map(node) do
    cond do
      Map.get(node, "isResolved", true) == true ->
        []

      true ->
        comments =
          node
          |> Map.get("comments", %{})
          |> Map.get("nodes", [])

        if comments == [] do
          []
        else
          total_count =
            node
            |> Map.get("comments", %{})
            |> Map.get("totalCount", nil)

          comments =
            comments
            |> Enum.map(fn c -> c || %{} end)
            |> Enum.sort_by(fn c -> to_string(Map.get(c, "createdAt", "")) end)

          comment_count = length(comments)

          opener = List.first(comments) || %{}
          latest = List.last(comments) || %{}

          {ask, ask_selected, ask_note} =
            if comment_count >= 2 and resolutionish_comment?(Map.get(latest, "body", "") || "") do
              prev = Enum.at(comments, -2) || latest
              {prev, "previous", "Selected previous comment as the ask because the latest comment looks like an acknowledgement/resolution."}
            else
              {latest, "latest", nil}
            end

          body = Map.get(ask, "body", "") || ""

          all_comments =
            Enum.map(comments, fn c ->
              %{
                author: get_in(c, ["author", "login"]) || "unknown",
                created_at: Map.get(c, "createdAt", "") || "",
                body: Map.get(c, "body", "") || ""
              }
            end)

          task = %{
            thread_id: Map.get(node, "id", "") || "",
            path: Map.get(node, "path", "") || "",
            line: Map.get(node, "line", nil),
            diff_side: blank_to_nil(Map.get(node, "diffSide", "")),
            type: classify_task(body),
            author: get_in(ask, ["author", "login"]) || "unknown",
            created_at: Map.get(ask, "createdAt", "") || "",
            body: body,
            comment_count: comment_count,
            comment_total_count: total_count,
            comments_truncated: is_integer(total_count) and total_count > comment_count,
            ask_selected: ask_selected,
            ask_note: ask_note,
            thread_opener: %{
              author: get_in(opener, ["author", "login"]) || "unknown",
              created_at: Map.get(opener, "createdAt", "") || "",
              body: Map.get(opener, "body", "") || ""
            },
            latest_comment: %{
              author: get_in(latest, ["author", "login"]) || "unknown",
              created_at: Map.get(latest, "createdAt", "") || "",
              body: Map.get(latest, "body", "") || ""
            },
            all_comments: if(length(all_comments) > 1, do: all_comments, else: nil)
          }

          [task]
        end
    end
  end

  defp sort_tasks(tasks) do
    Enum.sort_by(tasks, fn t ->
      {
        to_string(t.path || ""),
        if(is_integer(t.line), do: t.line, else: 1_000_000_000),
        to_string(t.created_at || ""),
        to_string(t.thread_id || "")
      }
    end)
  end

  defp json_array(items) when is_list(items) do
    inner =
      items
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.join(",\n")

    "[\n" <> inner <> "\n]\n"
  end

  defp blank_to_nil(s) do
    s = String.trim(to_string(s))
    if s == "", do: nil, else: s
  end

  defp ensure_clean_working_tree(root) do
    case System.cmd("git", ["status", "--porcelain"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        if String.trim(out) == "" do
          :ok
        else
          {:error,
           "Working tree has local changes. Please commit/stash/reset before running Codex reviews.\n\nOutput:\n#{out}"}
        end

      {out, _} ->
        {:error, "Failed to check git working tree status.\n\nOutput:\n#{out}"}
    end
  end

  defp ensure_on_recorded_pr_head(root, tasks_yaml_path) do
    head_ref =
      case read_yaml_scalar(tasks_yaml_path, "pr_head_ref") do
        {:ok, v} -> v
        _ -> ""
      end

    head_sha =
      case read_yaml_scalar(tasks_yaml_path, "pr_head_sha") do
        {:ok, v} -> v
        _ -> ""
      end

    with :ok <- ensure_on_recorded_pr_branch_name(root, head_ref),
         :ok <- ensure_contains_pr_head_commit(root, head_ref, head_sha) do
      :ok
    end
  end

  defp ensure_on_recorded_pr_branch_name(_root, ""), do: :ok

  defp ensure_on_recorded_pr_branch_name(root, head_ref) do
    case System.cmd("git", ["rev-parse", "--abbrev-ref", "HEAD"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        current = String.trim(out)

        if current == head_ref do
          :ok
        else
          IO.puts(:stderr, "WARN: You are on branch #{inspect(current)}, but this PR expects #{inspect(head_ref)}. Proceeding because HEAD-SHA validation is authoritative.")
          :ok
        end

      {out, _} ->
        {:error, "Failed to determine current git branch.\n\nOutput:\n#{out}"}
    end
  end

  defp ensure_contains_pr_head_commit(_root, _head_ref, ""), do: :ok

  defp ensure_contains_pr_head_commit(root, head_ref, head_sha) do
    case System.cmd("git", ["merge-base", "--is-ancestor", head_sha, "HEAD"], cd: root, stderr_to_stdout: true) do
      {_out, 0} ->
        :ok

      {out, _} ->
        {:error,
         "Current HEAD does not contain the PR head commit #{inspect(head_sha)} (branch #{inspect(head_ref)}).\n\nOutput:\n#{out}"}
    end
  end

  defp read_yaml_scalar(tasks_yaml_path, key) do
    with {:ok, content} <- File.read(tasks_yaml_path) do
      case Regex.run(~r/^#{Regex.escape(key)}:\s*"((?:\\.|[^"])*)"\s*$/m, content) do
        [_, quoted] -> {:ok, yaml_unescape_dq(quoted)}
        _ -> {:error, :missing}
      end
    end
  end

  defp yaml_unescape_dq(s) do
    s
    |> String.replace("\\\\", "\\")
    |> String.replace("\\\"", "\"")
  end

  defp ensure_agent_noninteractive(agent_cmd) do
    {out, status} = System.cmd(agent_cmd, ["exec", "--help"], stderr_to_stdout: true)

    if status == 0 do
      :ok
    else
      {:error,
       "Your Codex CLI must support `codex exec` for non-interactive runs.\n\nTried: #{agent_cmd} exec --help\n\nOutput:\n#{out}\n\nHint: upgrade Codex CLI, or set AGENT_CMD/CODEX_CMD to the correct Codex executable."}
    end
  end

  defp resolutionish_comment?(body) when is_binary(body) do
    lowered =
      body
      |> String.downcase()
      |> String.replace(~r/\s+/, " ")

    Enum.any?(
      [
        ~r/\blgtm\b/,
        ~r/\blooks good\b/,
        ~r/\bapproved\b/,
        ~r/\bresolved\b/,
        ~r/\bfixed\b/,
        ~r/\bdone\b/,
        ~r/\bnvm\b/,
        ~r/\bnever mind\b/,
        ~r/\bignore\b/,
        ~r/\bsgtm\b/,
        ~r/\bthanks\b/,
        ~r/\bthank you\b/
      ],
      fn re -> Regex.match?(re, lowered) end
    )
  end

  defp resolutionish_comment?(_), do: false

  defp classify_task(body) do
    lowered = String.downcase(body)

    cond do
      String.contains?(body, "?") or Enum.any?(["clarify", "why", "how", "what"], &String.contains?(lowered, &1)) ->
        "question"

      Enum.any?(["nit:", "minor", "style", "formatting"], &String.contains?(lowered, &1)) ->
        "nit"

      true ->
        "change"
    end
  end

  defp tasks_yaml(pr_title, pr_url, head_ref, base_ref, head_sha, base_sha, tasks) do
    header = [
      "pr_title: ",
      yaml_dq(pr_title),
      "\n",
      "pr_url: ",
      yaml_dq(pr_url),
      "\n",
      "pr_head_ref: ",
      yaml_dq(head_ref),
      "\n",
      "pr_base_ref: ",
      yaml_dq(base_ref),
      "\n",
      "pr_head_sha: ",
      yaml_dq(head_sha),
      "\n",
      "pr_base_sha: ",
      yaml_dq(base_sha),
      "\n"
    ]

    if tasks == [] do
      IO.iodata_to_binary([header, "tasks: []\n"])
    else
      items =
        tasks
        |> Enum.map(fn t ->
          [
            "  - id: ",
            Integer.to_string(t.id),
            "\n",
            "    thread_id: ",
            yaml_dq(t.thread_id),
            "\n",
            "    path: ",
            yaml_dq(t.path),
            "\n",
            "    line: ",
            if(is_integer(t.line), do: Integer.to_string(t.line), else: "null"),
            "\n",
            "    diff_side: ",
            if(is_binary(t.diff_side), do: yaml_dq(t.diff_side), else: "null"),
            "\n",
            "    type: ",
            yaml_dq(t.type),
            "\n",
            "    author: ",
            yaml_dq(t.author),
            "\n",
            "    created_at: ",
            yaml_dq(Map.get(t, :created_at, "")),
            "\n",
            "    comment_count: ",
            Integer.to_string(Map.get(t, :comment_count, 0)),
            "\n",
            "    comment_total_count: ",
            if(is_integer(Map.get(t, :comment_total_count, nil)), do: Integer.to_string(t.comment_total_count), else: "null"),
            "\n",
            "    comments_truncated: ",
            if(is_boolean(Map.get(t, :comments_truncated, nil)), do: yaml_bool(t.comments_truncated), else: "null"),
            "\n",
            "    ask_selected: ",
            yaml_dq(Map.get(t, :ask_selected, "latest")),
            "\n",
            "    ask_note: ",
            if(is_binary(Map.get(t, :ask_note, nil)), do: yaml_dq(t.ask_note), else: "null"),
            "\n",
            yaml_nested_comment(4, "thread_opener", Map.get(t, :thread_opener, %{})),
            yaml_nested_comment(4, "latest_comment", Map.get(t, :latest_comment, %{})),
            yaml_block(4, "body", t.body),
            yaml_all_comments(t.all_comments)
          ]
        end)

      IO.iodata_to_binary([header, "tasks:\n", items])
    end
  end

  defp yaml_bool(true), do: "true"
  defp yaml_bool(false), do: "false"

  defp yaml_nested_comment(indent, key, map) when is_map(map) do
    ind = String.duplicate(" ", indent)

    author = Map.get(map, :author) || Map.get(map, "author") || "unknown"
    created_at = Map.get(map, :created_at) || Map.get(map, "created_at") || ""
    body = Map.get(map, :body) || Map.get(map, "body") || ""

    [
      ind,
      key,
      ":\n",
      ind,
      "  author: ",
      yaml_dq(author),
      "\n",
      ind,
      "  created_at: ",
      yaml_dq(created_at),
      "\n",
      yaml_block(indent + 2, "body", body)
    ]
  end

  defp yaml_all_comments(nil), do: []

  defp yaml_all_comments(comments) when is_list(comments) do
    [
      "    all_comments:\n",
      Enum.map(comments, fn c ->
        [
          "      - author: ",
          yaml_dq(c.author),
          "\n",
          yaml_block(8, "body", c.body),
          "        created_at: ",
          yaml_dq(c.created_at),
          "\n"
        ]
      end)
    ]
  end

  defp yaml_dq(s) do
    escaped =
      s
      |> to_string()
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")

    ~s("#{escaped}")
  end

  defp yaml_block(indent, key, value) do
    ind = String.duplicate(" ", indent)
    value = to_string(value)

    [
      ind,
      key,
      ": |-\n",
      if(value == "",
        do: [],
        else:
          value
          |> String.split(["\r\n", "\n", "\r"], trim: false)
          |> Enum.map(fn line -> [ind, "  ", line, "\n"] end)
      )
    ]
  end

  defp tasks_md(pr_title, pr_url, tasks) do
    header = ["# PR Review Tasks: ", pr_title, "\n", "**PR:** ", pr_url, "\n\n"]

    if tasks == [] do
      IO.iodata_to_binary([header, "_No unresolved review threads found._\n"])
    else
      by_path =
        tasks
        |> Enum.group_by(fn t -> t.path || "(unknown)" end)

      sections =
        by_path
        |> Enum.sort_by(fn {path, _} -> path end)
        |> Enum.map(fn {path, items} ->
          [
            "## ",
            path,
            "\n",
            Enum.map(items, fn t ->
              summary = summarize(t.body)
              suffix = thread_suffix(t.thread_id)
              author = t.author || "unknown"

              {comments_label, multi?} =
                case Map.get(t, :comment_total_count) do
                  n when is_integer(n) and n > 0 ->
                    truncated? = Map.get(t, :comments_truncated, false) == true

                    if truncated? do
                      {"comments: last #{t.comment_count} of #{n}", n > 1}
                    else
                      {"comments: #{n}", n > 1}
                    end

                  _ ->
                    {"comments: #{Map.get(t, :comment_count, 1)}", Map.get(t, :comment_count, 1) > 1}
                end

              loc =
                if is_integer(t.line),
                  do: "line #{Integer.to_string(t.line)}",
                  else: "no line"

              meta =
                [
                  loc,
                  t.type,
                  "by #{author}",
                  "thread …#{suffix}",
                  comments_label
                ]
                |> Enum.join(", ")

              multi_note = if multi?, do: " (thread has multiple comments)", else: ""
              ["- [ ] Task ", Integer.to_string(t.id), " (", meta, "): ", summary, multi_note, "\n"]
            end),
            "\n"
          ]
        end)

      IO.iodata_to_binary([header, sections])
    end
  end

  defp thread_suffix(thread_id) when is_binary(thread_id) do
    tid = String.trim(thread_id)

    cond do
      tid == "" -> "????"
      String.length(tid) <= 8 -> tid
      true -> String.slice(tid, -8, 8)
    end
  end

  defp thread_suffix(_), do: "????"

  defp summarize(body) do
    first =
      body
      |> String.split(["\r\n", "\n", "\r"], trim: false)
      |> Enum.find_value(fn line ->
        stripped = String.trim(line)

        cond do
          stripped == "" -> nil
          String.starts_with?(stripped, "<details") -> nil
          String.starts_with?(stripped, "<summary") -> nil
          String.contains?(stripped, "Potential issue") -> nil
          Regex.match?(~r/^_.*_$/, stripped) -> nil
          String.starts_with?(stripped, "<!--") -> nil
          true -> stripped
        end
      end) || "(no content)"

    if String.length(first) > 100 do
      String.slice(first, 0, 97) <> "..."
    else
      first
    end
  end

  defp agent_prompt_template(opts) do
    """
    # PR Review Implementation Task

    Read `.agent/tasks.yaml` and implement/respond to each task systematically.

    ## Decision Framework
    For each task, choose ONE action:
    - **ACCEPT**: Implement the requested change
    - **ANSWER**: Provide clear response (for questions)
    - **PUSHBACK**: Decline with reasoning and alternative

    For tasks of type `"question"`, you should almost always **ANSWER** (unless the question is based on an incorrect assumption, in which case **PUSHBACK** with clarification).

    ## Implementation Guidelines
    - Make minimal, surgical changes only
    - Respect existing code style and patterns
    - Run appropriate test commands: `mix test`, `npm test`, `yarn test`, `pnpm test`
    - Fix test failures only if directly related to changes
    - NO broad refactoring, formatting changes, or new dependencies
    - NO commits or pushes
    ## Output Requirements (important)

    # Preferences
    - skip_nitpicks: #{if(Map.get(opts, :skip_nitpicks, false), do: "true", else: "false")}

    If `skip_nitpicks` is true, then for tasks with type `"nit"` you should default to **PUSHBACK** with a short acknowledgement (do not spend time implementing nits unless they are correctness/security issues).

    - You MUST list **all** tasks from `.agent/tasks.yaml` in order (Task 1..N).
    - For each task, include a short excerpt of the original ask so a developer can understand the request without opening GitHub.
    - For **ACCEPT** decisions: be concise (what changed + which files).
    - For **ANSWER** and **PUSHBACK** decisions: be more verbose with reasoning, and include small examples/snippets when helpful. The response should be copy-paste ready for GitHub.

    ### Summary
    - Changes made: [brief list]
    - Tests run: [command + status]
    - Overall status: [success/partial/issues]

    ### Task Responses
    For each task, use this structure:

    #### Task 1: `path:line` (`type`)
    **Ask (excerpt):** "..."
    **Decision:** ACCEPT | ANSWER | PUSHBACK
    - For ACCEPT: bullets describing the exact changes and filenames.
    - For ANSWER/PUSHBACK: include a **Reply** section with full markdown body ready to paste into GitHub.

    ---

    ## Posting Metadata (required)
    At the very end of your output, include a single JSON code block (fenced with ```json) with this exact shape:

    ```json
    {
      "replies": [
        {
          "task_id": 2,
          "thread_id": "PRRT_kwDO...",
          "decision": "ANSWER",
          "body": "Your reply body (markdown allowed). This should match the Reply section for that task."
        }
      ],
      "top_level_comment": "Optional short PR summary comment (keep concise)."
    }
    ```

    Rules:
    - Include a `replies[]` entry for each task you **ANSWER** or **PUSHBACK** (one per task).
    - `thread_id` must come from `.agent/tasks.yaml` for that task.
    - `decision` must be `ANSWER` or `PUSHBACK`.
    - `top_level_comment` may be an empty string if you don't want a top-level PR comment.
    - The JSON block must be the final fenced ```json block at the end of the file (no other JSON blocks after it).
    """
  end

  defp write_run_md(root, fetch_ctx) do
    agent_dir = Path.join(root, @agent_dir)
    File.mkdir_p!(agent_dir)

    type_counts =
      fetch_ctx.tasks
      |> Enum.map(& &1.type)
      |> Enum.frequencies()
      |> Enum.sort_by(fn {type, _} -> type end)

    changed_files = changed_files(root)

    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    tasks_yaml = Path.join(agent_dir, "tasks.yaml") |> Path.relative_to(root)
    tasks_md = Path.join(agent_dir, "tasks.md") |> Path.relative_to(root)
    responses_md = Path.join(agent_dir, "review_responses.md") |> Path.relative_to(root)

    content =
      [
        "# Codex Reviews Run\n",
        "\n",
        "- Timestamp (UTC): ",
        now,
        "\n",
        "- PR: ",
        fetch_ctx.pr_url,
        "\n",
        "- Title: ",
        fetch_ctx.pr_title,
        "\n",
        "\n",
        "## Tasks\n",
        "- Total: ",
        Integer.to_string(length(fetch_ctx.tasks)),
        "\n",
        Enum.map(type_counts, fn {type, count} ->
          ["- ", type, ": ", Integer.to_string(count), "\n"]
        end),
        "\n",
        "## Outputs\n",
        "- `",
        tasks_yaml,
        "`\n",
        "- `",
        tasks_md,
        "`\n",
        "- `",
        responses_md,
        "`\n",
        "\n",
        "## Working Tree\n",
        if(changed_files == [],
          do: "_No local changes detected._\n",
          else: Enum.map(changed_files, fn f -> ["- `", f, "`\n"] end)
        )
      ]
      |> IO.iodata_to_binary()

    run_path = Path.join(agent_dir, "run.md")
    File.write!(run_path, content)
    IO.puts("Wrote: #{run_path}")
    {:ok, run_path}
  end

  defp changed_files(root) do
    unstaged = git_lines(root, ["diff", "--name-only"])
    staged = git_lines(root, ["diff", "--name-only", "--cached"])

    (unstaged ++ staged)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp git_lines(root, args) do
    case System.cmd("git", args, cd: root, stderr_to_stdout: true) do
      {out, 0} -> String.split(out, "\n", trim: true)
      _ -> []
    end
  end

  defp write_changes_patch!(root, patch_path) do
    staged = git_out(root, ["diff", "--cached"])
    unstaged = git_out(root, ["diff"])

    content =
      cond do
        String.trim(staged) == "" and String.trim(unstaged) == "" ->
          "No changes.\n"

        true ->
          [
            "# Staged changes (git diff --cached)\n",
            if(String.trim(staged) == "", do: "(none)\n\n", else: staged <> "\n\n"),
            "# Unstaged changes (git diff)\n",
            if(String.trim(unstaged) == "", do: "(none)\n", else: unstaged <> "\n")
          ]
          |> IO.iodata_to_binary()
      end

    File.write!(patch_path, content)
    IO.puts("Wrote: #{patch_path}")
    :ok
  end

  defp git_out(root, args) do
    case System.cmd("git", args, cd: root, stderr_to_stdout: true) do
      {out, 0} -> out
      {out, _} -> out
    end
  end

  defp detect_posting_metadata(root, responses_md) do
    case File.read(responses_md) do
      {:ok, content} ->
        case extract_posting_metadata(content, root) do
          {:ok, %{"replies" => replies, "top_level_comment" => top_level_comment}} ->
            %{
              status: :ok,
              replies: length(replies),
              top_level?: String.trim(to_string(top_level_comment)) != ""
            }

          {:error, reason} ->
            reason = to_string(reason)

            if String.contains?(reason, "Could not find a JSON posting metadata") do
              %{status: :missing}
            else
            %{
              status: :invalid,
              reason: reason
            }
            end
        end

      _ ->
        %{status: :missing}
    end
  end

  defp maybe_commit(_root, _tasks_yaml, %{commit?: false}), do: %{enabled?: false}

  defp maybe_commit(root, tasks_yaml, %{commit?: true}) do
    case System.cmd("git", ["status", "--porcelain"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        if String.trim(out) == "" do
          %{enabled?: true, committed?: false, reason: :no_changes}
        else
          msg = default_commit_message(tasks_yaml)

          {add_out, add_status} = System.cmd("git", ["add", "-A"], cd: root, stderr_to_stdout: true)

          if add_status != 0 do
            {:error, "Failed to stage changes for commit.\n\nOutput:\n#{add_out}"}
          else
            {commit_out, commit_status} = System.cmd("git", ["commit", "-m", msg], cd: root, stderr_to_stdout: true)

            if commit_status != 0 do
              {:error,
               "Failed to commit changes.\n\nOutput:\n#{commit_out}\n\nHint: ensure git user.name/user.email are configured."}
            else
              sha =
                case System.cmd("git", ["rev-parse", "HEAD"], cd: root, stderr_to_stdout: true) do
                  {sha_out, 0} -> String.trim(sha_out)
                  _ -> ""
                end

              %{enabled?: true, committed?: true, sha: sha, message: msg}
            end
          end
        end

      {out, _} ->
        {:error, "Failed to check git status.\n\nOutput:\n#{out}"}
    end
  end

  defp default_commit_message(tasks_yaml) do
    pr_url =
      case read_yaml_scalar(tasks_yaml, "pr_url") do
        {:ok, v} -> v
        _ -> ""
      end

    pr_number =
      case Regex.run(~r{/pull/(\d+)}i, pr_url) do
        [_, n] -> n
        _ -> nil
      end

    if is_binary(pr_number) do
      "Address PR review feedback (##{pr_number})"
    else
      "Address PR review feedback"
    end
  end

  defp parse_pr_ref(ref, root) do
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
    case System.cmd("git", ["config", "--get", "remote.origin.url"], cd: root, stderr_to_stdout: true) do
      {remote, 0} ->
        case parse_github_remote(String.trim(remote)) do
          {:ok, owner, repo} -> {:ok, {owner, repo}}
          :error -> {:error, "Could not infer GitHub repo from remote.origin.url (pass a PR URL instead)"}
        end

      {out, _} ->
        {:error, "Could not read remote.origin.url.\n\nOutput:\n#{out}"}
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

  # Shellwords splitting: supports spaces, single/double quotes, and backslash escapes (in normal/double quotes).
  defp shellwords(""), do: []

  defp shellwords(s) do
    s
    |> String.trim()
    |> do_shellwords([], "", :normal, false)
    |> Enum.reverse()
  end

  defp do_shellwords(<<>>, acc, "", _mode, _escape), do: acc
  defp do_shellwords(<<>>, acc, token, _mode, _escape), do: [token | acc]

  defp do_shellwords(<<"\\", rest::binary>>, acc, token, :single, false),
    do: do_shellwords(rest, acc, token <> "\\", :single, false)

  defp do_shellwords(<<"\\", rest::binary>>, acc, token, mode, false) when mode in [:normal, :double],
    do: do_shellwords(rest, acc, token, mode, true)

  defp do_shellwords(<<char::utf8, rest::binary>>, acc, token, mode, true),
    do: do_shellwords(rest, acc, token <> <<char::utf8>>, mode, false)

  defp do_shellwords(<<"\"", rest::binary>>, acc, token, :normal, false),
    do: do_shellwords(rest, acc, token, :double, false)

  defp do_shellwords(<<"\"", rest::binary>>, acc, token, :double, false),
    do: do_shellwords(rest, acc, token, :normal, false)

  defp do_shellwords(<<"'", rest::binary>>, acc, token, :normal, false),
    do: do_shellwords(rest, acc, token, :single, false)

  defp do_shellwords(<<"'", rest::binary>>, acc, token, :single, false),
    do: do_shellwords(rest, acc, token, :normal, false)

  defp do_shellwords(<<char::utf8, rest::binary>>, acc, token, :normal, false) when char in [?\s, ?\t, ?\n, ?\r] do
    if token == "" do
      do_shellwords(rest, acc, "", :normal, false)
    else
      do_shellwords(rest, [token | acc], "", :normal, false)
    end
  end

  defp do_shellwords(<<char::utf8, rest::binary>>, acc, token, mode, false),
    do: do_shellwords(rest, acc, token <> <<char::utf8>>, mode, false)

  # Posting metadata parsing (stdlib-only JSON parser)
  defp extract_posting_metadata(content, root) do
    with {:ok, block} <- extract_final_json_fence(content),
         {:ok, normalized} <- normalize_posting_metadata_json(block, root),
         {:ok, decoded} <- parse_posting_metadata_json(normalized) do
      {:ok, decoded}
    else
      {:error, msg} -> {:error, msg}
    end
  rescue
    _ -> {:error, "Failed to parse JSON posting metadata block. Ensure the final fenced ```json block is valid JSON."}
  end

  defp extract_final_json_fence(content) when is_binary(content) do
    case Regex.run(
           ~r/```[ \t]*(json|jsonc)[ \t]*\r?\n(.*?)\r?\n```[ \t]*\r?\n?\s*\z/si,
           content,
           capture: :all_but_first
         ) do
      [lang, body] when is_binary(lang) and is_binary(body) ->
        {:ok, String.trim(body)}

      _ ->
        if Regex.match?(~r/```[ \t]*(json|jsonc)[ \t]*\r?\n/si, content) do
          {:error,
           "Found a JSON code block, but posting metadata must be the FINAL fenced ```json block at the end of `.agent/review_responses.md`."}
        else
          {:error, "Could not find a JSON posting metadata code block (```json ... ```) in `.agent/review_responses.md`."}
        end
    end
  end

  defp normalize_posting_metadata_json(block, root) do
    jq = System.find_executable("jq")
    python = System.find_executable("python3")

    agent_dir = Path.join(root, @agent_dir)
    File.mkdir_p!(agent_dir)
    tmp = Path.join(agent_dir, "posting_metadata.json")
    File.write!(tmp, block)

    cond do
      is_binary(jq) ->
        {out, status} = System.cmd(jq, ["-c", ".", tmp], stderr_to_stdout: true)

        if status == 0 do
          {:ok, String.trim(out)}
        else
          {:error, "Invalid JSON posting metadata (jq failed).\n\nOutput:\n#{out}"}
        end

      is_binary(python) ->
        py =
          "import json,sys; p=sys.argv[1]; obj=json.load(open(p,'r',encoding='utf-8')); print(json.dumps(obj, ensure_ascii=False, separators=(',',':')))"

        {out, status} = System.cmd(python, ["-c", py, tmp], stderr_to_stdout: true)

        if status == 0 do
          {:ok, String.trim(out)}
        else
          {:error, "Invalid JSON posting metadata (python3 failed).\n\nOutput:\n#{out}"}
        end

      true ->
        {:ok, block}
    end
  end

  defp parse_posting_metadata_json(json) when is_binary(json) do
    case Json.parse(json) do
      {:ok, %{"replies" => replies} = decoded} when is_list(replies) ->
        {:ok,
         %{
           "replies" => replies,
           "top_level_comment" => Map.get(decoded, "top_level_comment", "")
         }}

      {:ok, _} ->
        {:error, "Posting metadata JSON is valid, but it doesn't match the required shape: {replies: [...], top_level_comment: \"...\"}."}

      {:error, reason} ->
        {:error,
         "Failed to parse posting metadata JSON (#{inspect(reason)}). If this persists, install `jq` or `python3` so the script can validate/normalize JSON more robustly."}
    end
  end

  defp post_thread_replies(root, replies, task_map) do
    agent_dir = Path.join(root, @agent_dir)
    File.mkdir_p!(agent_dir)
    errors_log = Path.join(agent_dir, "post_errors.log")
    File.write!(errors_log, "")

    {posted, failed} =
      Enum.reduce(replies, {0, 0}, fn reply, {posted, failed} ->
        with {:ok, decision} <- fetch_string(reply, "decision"),
             true <- decision in ["ANSWER", "PUSHBACK"],
             {:ok, task_id} <- fetch_int(reply, "task_id"),
             {:ok, thread_id} <- fetch_string(reply, "thread_id"),
             :ok <- validate_reply_target(task_map, task_id, thread_id),
             {:ok, body} <- fetch_string(reply, "body"),
             body_trim <- String.trim(body),
             true <- body_trim != "" do
          case post_thread_reply(root, thread_id, body_trim) do
            :ok ->
              {posted + 1, failed}

            {:error, out} ->
              append_post_error!(errors_log, "task_id=#{task_id} thread_id=#{thread_id}", out)
              IO.puts(:stderr, "ERROR: Failed to post reply for task_id=#{task_id} (see #{errors_log}).")
              {posted, failed + 1}
          end
        else
          {:ok, decision} ->
            IO.puts(:stderr, "WARN: Skipping reply with decision=#{inspect(decision)} (only ANSWER/PUSHBACK are posted).")
            {posted, failed}

          {:error, msg} ->
            IO.puts(:stderr, "WARN: Skipping malformed reply entry: #{msg}")
            {posted, failed}

          false ->
            IO.puts(:stderr, "WARN: Skipping malformed reply entry.")
            {posted, failed}
        end
      end)

    if failed == 0 do
      {:ok, posted}
    else
      {:error,
       "Some thread replies failed to post (posted=#{posted}, failed=#{failed}).\nSee: #{errors_log}\n\nCommon causes: missing permissions (fork PR), GitHub auth scope, or rate limits."}
    end
  end

  defp fetch_string(map, key) when is_map(map) do
    case Map.get(map, key) do
      v when is_binary(v) -> {:ok, v}
      v -> {:error, "Expected string for #{key}, got: #{inspect(v)}"}
    end
  end

  defp fetch_int(map, key) when is_map(map) do
    case Map.get(map, key) do
      v when is_integer(v) -> {:ok, v}
      v -> {:error, "Expected integer for #{key}, got: #{inspect(v)}"}
    end
  end

  defp validate_reply_target(task_map, task_id, thread_id) do
    case Map.get(task_map, task_id) do
      nil ->
        {:error, "Unknown task_id=#{task_id} (not found in .agent/tasks.yaml)"}

      ^thread_id ->
        :ok

      other ->
        {:error,
         "thread_id mismatch for task_id=#{task_id}: metadata has #{inspect(thread_id)}, but .agent/tasks.yaml has #{inspect(other)}"}
    end
  end

  defp parse_tasks_yaml_for_posting(path) do
    with {:ok, content} <- File.read(path) do
      lines = String.split(content, "\n", trim: false)
      {:ok, parse_tasks_yaml_thread_map(lines, %{}, nil, :normal)}
    end
  end

  defp parse_tasks_yaml_thread_map([], acc, _current_id, _state), do: acc

  defp parse_tasks_yaml_thread_map([line | rest], acc, current_id, :in_body) do
    if Regex.match?(~r/^\s{6}/, line) do
      parse_tasks_yaml_thread_map(rest, acc, current_id, :in_body)
    else
      parse_tasks_yaml_thread_map([line | rest], acc, current_id, :normal)
    end
  end

  defp parse_tasks_yaml_thread_map([line | rest], acc, current_id, :normal) do
    cond do
      Regex.match?(~r/^\s{2}-\s+id:\s+(\d+)\s*$/, line) ->
        [_, id_str] = Regex.run(~r/^\s{2}-\s+id:\s+(\d+)\s*$/, line)
        parse_tasks_yaml_thread_map(rest, acc, String.to_integer(id_str), :normal)

      is_integer(current_id) and Regex.match?(~r/^\s{4}thread_id:\s+"(.*)"\s*$/, line) ->
        [_, tid] = Regex.run(~r/^\s{4}thread_id:\s+"(.*)"\s*$/, line)
        acc = Map.put(acc, current_id, yaml_unescape_dq(tid))
        parse_tasks_yaml_thread_map(rest, acc, current_id, :normal)

      is_integer(current_id) and Regex.match?(~r/^\s{4}body:\s+\|-\s*$/, line) ->
        parse_tasks_yaml_thread_map(rest, acc, current_id, :in_body)

      true ->
        parse_tasks_yaml_thread_map(rest, acc, current_id, :normal)
    end
  end

  defp wrap_review_responses!(root, tasks_yaml, responses_raw_md, responses_md, exec_log) do
    raw =
      case File.read(responses_raw_md) do
        {:ok, s} -> String.trim_trailing(s) <> "\n"
        _ -> ""
      end

    tasks = parse_tasks_yaml_for_wrapper(tasks_yaml)

    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    header =
      [
        "# PR Review Responses\n",
        "\n",
        "- Timestamp (UTC): ",
        now,
        "\n",
        "- Tasks: `",
        Path.relative_to(tasks_yaml, root),
        "`\n",
        "- Raw: `",
        Path.relative_to(responses_raw_md, root),
        "`\n",
        "- Logs: `",
        Path.relative_to(exec_log, root),
        "`\n",
        "\n",
        "## Task List\n",
        tasks,
        "\n",
        "---\n",
        "\n",
        "## Codex Output (Last Message)\n",
        "\n"
      ]
      |> IO.iodata_to_binary()

    File.write!(responses_md, header <> raw)
    IO.puts("Wrote: #{responses_md}")
  end

  defp parse_tasks_yaml_for_wrapper(path) do
    with {:ok, content} <- File.read(path) do
      lines = String.split(content, "\n", trim: false)
      tasks = parse_tasks_yaml_for_wrapper_tasks(lines, [], nil, %{}, :outside)

      if tasks == [] do
        "_No tasks found._\n"
      else
        tasks
        |> Enum.map(fn t ->
          loc =
            if is_integer(t.line) do
              "#{t.path}:#{t.line}"
            else
              t.path
            end

          author = Map.get(t, :author, "unknown")
          type = Map.get(t, :type, "change")
          suffix = thread_suffix(Map.get(t, :thread_id, ""))

          comments =
            case Map.get(t, :comment_total_count) do
              n when is_integer(n) and n > 0 ->
                truncated? = Map.get(t, :comments_truncated, false) == true

                if truncated? do
                  "comments: last #{Map.get(t, :comment_count, 0)} of #{n}"
                else
                  "comments: #{n}"
                end

              _ ->
                "comments: #{Map.get(t, :comment_count, 0)}"
            end

          ask_selected = Map.get(t, :ask_selected, "latest")
          ask_note = Map.get(t, :ask_note, nil)

          ask = Map.get(t, :body, "")
          ask_excerpt = wrapper_excerpt(ask)

          [
            "- Task ",
            Integer.to_string(t.id),
            ": `",
            loc,
            "` (",
            type,
            ", by ",
            author,
            ", thread …",
            suffix,
            ", ",
            comments,
            ")\n",
            "  - Ask (",
            ask_selected,
            "): ",
            ask_excerpt,
            "\n",
            if(is_binary(ask_note) and String.trim(ask_note) != "", do: ["  - Note: ", wrapper_excerpt(ask_note), "\n"], else: [])
          ]
        end)
      end
    else
      _ -> "_No tasks found._\n"
    end
  end

  defp parse_tasks_yaml_for_wrapper_tasks([], acc, nil, _cur, _state), do: Enum.reverse(acc)

  defp parse_tasks_yaml_for_wrapper_tasks([], acc, _cur_id, cur, _state),
    do: Enum.reverse([finalize_wrapper_task(cur) | acc])

  defp parse_tasks_yaml_for_wrapper_tasks([line | rest], acc, cur_id, cur, :in_body) do
    if Regex.match?(~r/^\s{6}/, line) do
      # Strip the 6-space indentation used by yaml_block/3.
      body_line = String.replace_prefix(line, "      ", "")
      cur = append_body_line(cur, body_line)
      parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, cur, :in_body)
    else
      parse_tasks_yaml_for_wrapper_tasks([line | rest], acc, cur_id, cur, :in_task)
    end
  end

  defp parse_tasks_yaml_for_wrapper_tasks([line | rest], acc, cur_id, cur, state) do
    cond do
      Regex.match?(~r/^\s{2}-\s+id:\s+(\d+)\s*$/, line) ->
        [_, id_str] = Regex.run(~r/^\s{2}-\s+id:\s+(\d+)\s*$/, line)
        next_id = String.to_integer(id_str)

        acc =
          if is_integer(cur_id) do
            [finalize_wrapper_task(cur) | acc]
          else
            acc
          end

        parse_tasks_yaml_for_wrapper_tasks(rest, acc, next_id, %{id: next_id, body_lines: []}, :in_task)

      state == :in_task and Regex.match?(~r/^\s{4}thread_id:\s+"(.*)"\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}thread_id:\s+"(.*)"\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :thread_id, yaml_unescape_dq(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}path:\s+"(.*)"\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}path:\s+"(.*)"\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :path, yaml_unescape_dq(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}line:\s+(\d+)\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}line:\s+(\d+)\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :line, String.to_integer(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}line:\s+null\s*$/, line) ->
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :line, nil), state)

      state == :in_task and Regex.match?(~r/^\s{4}type:\s+"(.*)"\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}type:\s+"(.*)"\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :type, yaml_unescape_dq(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}author:\s+"(.*)"\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}author:\s+"(.*)"\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :author, yaml_unescape_dq(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}comment_count:\s+(\d+)\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}comment_count:\s+(\d+)\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :comment_count, String.to_integer(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}comment_total_count:\s+(\d+)\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}comment_total_count:\s+(\d+)\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :comment_total_count, String.to_integer(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}comments_truncated:\s+(true|false)\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}comments_truncated:\s+(true|false)\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :comments_truncated, v == "true"), state)

      state == :in_task and Regex.match?(~r/^\s{4}ask_selected:\s+"(.*)"\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}ask_selected:\s+"(.*)"\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :ask_selected, yaml_unescape_dq(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}ask_note:\s+"(.*)"\s*$/, line) ->
        [_, v] = Regex.run(~r/^\s{4}ask_note:\s+"(.*)"\s*$/, line)
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :ask_note, yaml_unescape_dq(v)), state)

      state == :in_task and Regex.match?(~r/^\s{4}ask_note:\s+null\s*$/, line) ->
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, Map.put(cur, :ask_note, nil), state)

      state == :in_task and Regex.match?(~r/^\s{4}body:\s+\|-\s*$/, line) ->
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, cur, :in_body)

      true ->
        parse_tasks_yaml_for_wrapper_tasks(rest, acc, cur_id, cur, state)
    end
  end

  defp append_body_line(cur, line) do
    # Keep wrapper parsing bounded (we only need an excerpt).
    max_chars = 4000
    body = Map.get(cur, :body_acc, "")

    if byte_size(body) >= max_chars do
      cur
    else
      body = if body == "", do: line, else: body <> "\n" <> line
      Map.put(cur, :body_acc, body)
    end
  end

  defp finalize_wrapper_task(cur) do
    body = Map.get(cur, :body_acc, "")

    cur
    |> Map.put(:body, body)
    |> Map.delete(:body_acc)
    |> Map.delete(:body_lines)
  end

  defp wrapper_excerpt(text) when is_binary(text) do
    s =
      text
      |> String.replace(~r/\s+/, " ")
      |> String.trim()

    cond do
      s == "" -> "(no content)"
      String.length(s) <= 220 -> s
      true -> String.slice(s, 0, 217) <> "..."
    end
  end

  defp wrapper_excerpt(_), do: "(no content)"

  defp append_post_error!(errors_log, label, out) do
    header = "\n---\n#{label}\n---\n"
    File.write!(errors_log, header <> out <> "\n", [:append])
  end

  defp post_thread_reply(root, thread_id, body) do
    query = """
    mutation($id: ID!, $body: String!) {
      addPullRequestReviewThreadReply(input: { pullRequestReviewThreadId: $id, body: $body }) {
        comment { id }
      }
    }
    """

    agent_dir = Path.join(root, @agent_dir)
    File.mkdir_p!(agent_dir)
    body_path = Path.join(agent_dir, "thread_reply_body.md")
    File.write!(body_path, body)

    args = [
      "api",
      "graphql",
      "-f",
      "query=#{query}",
      "-f",
      "id=#{thread_id}",
      "-F",
      "body=@#{body_path}"
    ]

    case System.cmd("gh", args, stderr_to_stdout: true) do
      {_out, 0} ->
        :ok

      {out, _} ->
        {:error, out}
    end
  end

  defp maybe_post_top_level_comment(root, pr_ref, top_level_comment) when is_binary(top_level_comment) do
    if String.trim(top_level_comment) == "" do
      :ok
    else
      agent_dir = Path.join(root, @agent_dir)
      File.mkdir_p!(agent_dir)
      path = Path.join(agent_dir, "top_level_comment.md")
      File.write!(path, top_level_comment)

      case System.cmd("gh", ["pr", "comment", pr_ref, "--body-file", path], stderr_to_stdout: true) do
        {_out, 0} -> :ok
        {out, _} -> {:error, "Failed to post top-level PR comment.\n\nOutput:\n#{out}"}
      end
    end
  end

  defp maybe_post_top_level_comment(_root, _pr_ref, _), do: :ok
end

defmodule Json do
  def parse(binary) when is_binary(binary) do
    binary = String.trim(binary)
    case value(binary, 0) do
      {:ok, val, idx} ->
        idx = skip_ws(binary, idx)
        if idx == byte_size(binary), do: {:ok, val}, else: {:error, :trailing}

      other ->
        other
    end
  end

  defp value(bin, idx) do
    idx = skip_ws(bin, idx)

    case at(bin, idx) do
      ?{ -> object(bin, idx + 1, %{})
      ?[ -> array(bin, idx + 1, [])
      ?" -> string(bin, idx + 1, "")
      ?t -> literal(bin, idx, "true", true)
      ?f -> literal(bin, idx, "false", false)
      ?n -> literal(bin, idx, "null", nil)
      c when c == ?- or (c >= ?0 and c <= ?9) -> number(bin, idx)
      _ -> {:error, :invalid}
    end
  end

  defp object(bin, idx, acc) do
    idx = skip_ws(bin, idx)

    if at(bin, idx) == ?} do
      {:ok, acc, idx + 1}
    else
      with {:ok, key, idx} <- expect_string(bin, idx),
           idx <- skip_ws(bin, idx),
           true <- at(bin, idx) == ?:,
           {:ok, val, idx} <- value(bin, idx + 1),
           acc <- Map.put(acc, key, val),
           idx <- skip_ws(bin, idx) do
        case at(bin, idx) do
          ?, -> object(bin, idx + 1, acc)
          ?} -> {:ok, acc, idx + 1}
          _ -> {:error, :object_delim}
        end
      else
        _ -> {:error, :object}
      end
    end
  end

  defp array(bin, idx, acc) do
    idx = skip_ws(bin, idx)

    if at(bin, idx) == ?] do
      {:ok, Enum.reverse(acc), idx + 1}
    else
      with {:ok, val, idx} <- value(bin, idx),
           acc <- [val | acc],
           idx <- skip_ws(bin, idx) do
        case at(bin, idx) do
          ?, -> array(bin, idx + 1, acc)
          ?] -> {:ok, Enum.reverse(acc), idx + 1}
          _ -> {:error, :array_delim}
        end
      else
        _ -> {:error, :array}
      end
    end
  end

  defp expect_string(bin, idx) do
    idx = skip_ws(bin, idx)
    if at(bin, idx) == ?", do: string(bin, idx + 1, ""), else: {:error, :expected_string}
  end

  defp string(bin, idx, acc) do
    case at(bin, idx) do
      ?" ->
        {:ok, acc, idx + 1}

      ?\\ ->
        case at(bin, idx + 1) do
          ?" -> string(bin, idx + 2, acc <> "\"")
          ?\\ -> string(bin, idx + 2, acc <> "\\")
          ?/ -> string(bin, idx + 2, acc <> "/")
          ?b -> string(bin, idx + 2, acc <> <<8>>)
          ?f -> string(bin, idx + 2, acc <> <<12>>)
          ?n -> string(bin, idx + 2, acc <> "\n")
          ?r -> string(bin, idx + 2, acc <> "\r")
          ?t -> string(bin, idx + 2, acc <> "\t")
          ?u ->
            with {:ok, codepoint, next} <- unicode_escape(bin, idx + 2) do
              string(bin, next, acc <> <<codepoint::utf8>>)
            else
              _ -> {:error, :unicode}
            end

          _ ->
            {:error, :escape}
        end

      c when is_integer(c) and c >= 0 ->
        # Decode unescaped UTF-8 codepoints correctly (GitHub API responses contain raw UTF-8).
        rest = :binary.part(bin, idx, byte_size(bin) - idx)

        case String.next_codepoint(rest) do
          {cp, rest2} ->
            consumed = byte_size(rest) - byte_size(rest2)
            string(bin, idx + consumed, acc <> cp)

          nil ->
            {:error, :string}
        end

      _ ->
        {:error, :string}
    end
  end

  defp unicode_escape(bin, idx) do
    with {:ok, first, next} <- unicode_escape_4(bin, idx) do
      cond do
        first in 0xD800..0xDBFF ->
          # High surrogate; must be followed by a low surrogate escape.
          if slice(bin, next, 2) == "\\u" do
            with {:ok, second, next2} <- unicode_escape_4(bin, next + 2),
                 true <- second in 0xDC00..0xDFFF do
              codepoint = 0x10000 + Bitwise.bsl(first - 0xD800, 10) + (second - 0xDC00)

              if codepoint <= 0x10FFFF do
                {:ok, codepoint, next2}
              else
                {:error, :unicode_range}
              end
            else
              _ -> {:error, :unicode_surrogate}
            end
          else
            {:error, :unicode_surrogate}
          end

        first in 0xDC00..0xDFFF ->
          # Lone low surrogate.
          {:error, :unicode_surrogate}

        true ->
          {:ok, first, next}
      end
    end
  end

  defp unicode_escape_4(bin, idx) do
    hex = slice(bin, idx, 4)

    case Integer.parse(hex, 16) do
      {n, ""} -> {:ok, n, idx + 4}
      _ -> {:error, :unicode_hex}
    end
  end

  defp number(bin, idx) do
    case scan_number(bin, idx) do
      {:ok, num_str, next, :int} ->
        case Integer.parse(num_str) do
          {n, ""} -> {:ok, n, next}
          _ -> {:error, :number}
        end

      {:ok, num_str, next, :float} ->
        case Float.parse(num_str) do
          {n, ""} -> {:ok, n, next}
          _ -> {:error, :number}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # JSON number grammar: -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?
  defp scan_number(bin, idx) do
    start = idx
    idx = if at(bin, idx) == ?-, do: idx + 1, else: idx

    {idx, _int_kind} =
      case at(bin, idx) do
        ?0 ->
          {idx + 1, :zero}

        c when c >= ?1 and c <= ?9 ->
          {take_digits(bin, idx + 1), :nonzero}

        _ ->
          {-1, :invalid}
      end

    if idx < 0 do
      {:error, :number}
    else
      {idx, has_frac?} =
        if at(bin, idx) == ?. do
          idx = idx + 1

          if at(bin, idx) >= ?0 and at(bin, idx) <= ?9 do
            {take_digits(bin, idx + 1), true}
          else
            {-1, false}
          end
        else
          {idx, false}
        end

      if idx < 0 do
        {:error, :number}
      else
        {idx, has_exp?} =
          if at(bin, idx) in [?e, ?E] do
            idx = idx + 1
            idx = if at(bin, idx) in [?+, ?-], do: idx + 1, else: idx

            if at(bin, idx) >= ?0 and at(bin, idx) <= ?9 do
              {take_digits(bin, idx + 1), true}
            else
              {-1, false}
            end
          else
            {idx, false}
          end

        if idx < 0 do
          {:error, :number}
        else
          num_str = :binary.part(bin, start, idx - start)
          kind = if has_frac? or has_exp?, do: :float, else: :int
          {:ok, num_str, idx, kind}
        end
      end
    end
  end

  defp take_digits(bin, idx) do
    case at(bin, idx) do
      c when c >= ?0 and c <= ?9 -> take_digits(bin, idx + 1)
      _ -> idx
    end
  end

  defp literal(bin, idx, lit, value) do
    if slice(bin, idx, byte_size(lit)) == lit do
      {:ok, value, idx + byte_size(lit)}
    else
      {:error, :literal}
    end
  end

  defp skip_ws(bin, idx) do
    case at(bin, idx) do
      c when c in [?\s, ?\t, ?\n, ?\r] -> skip_ws(bin, idx + 1)
      _ -> idx
    end
  end

  defp at(bin, idx) when idx >= byte_size(bin), do: -1
  defp at(bin, idx), do: :binary.at(bin, idx)

  defp slice(bin, idx, len) do
    if idx + len <= byte_size(bin) do
      :binary.part(bin, idx, len)
    else
      ""
    end
  end
end

CodexReviews.main(System.argv())
