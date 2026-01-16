defmodule AgentReviews.CLI do
  @agent_dir ".agent_review"

  def main(argv) when is_list(argv) do
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
        model: nil,
        reasoning_effort: nil,
        repo: nil,
        commit?: false,
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

  defp parse_opts(["--model", model | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | model: model}, rest_rev)

  defp parse_opts(["--reasoning-effort", effort | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | reasoning_effort: effort}, rest_rev)

  defp parse_opts(["--worktree" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | worktree?: true}, rest_rev)

  defp parse_opts(["--worktree-dir", dir | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | worktree_dir: dir}, rest_rev)

  defp parse_opts(["--commit" | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | commit?: true}, rest_rev)

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

      ["run", pr_ref] ->
        run_with_worktree_if_enabled(root, pr_ref, opts)

      ["post", pr_ref] ->
        if Map.get(opts, :worktree?, false) do
          {:error, "--worktree is only supported for `run` (cd into the worktree and run `post` there)."}
        else
          _ = ensure_repo_local_exclude(root)
          case run_post(root, pr_ref, opts) do
            {:ok, post_ctx} ->
              print_post_summary(root, pr_ref, post_ctx, opts)
              :ok

            other ->
              other
          end
        end

      [pr_ref] ->
        run_with_worktree_if_enabled(root, pr_ref, opts)

      [] ->
        usage(opts.invoke)
        {:error, "Missing arguments"}

      ["post"] ->
        usage(opts.invoke)
        {:error, "Missing PR reference for `post`"}

      ["run"] ->
        usage(opts.invoke)
        {:error, "Missing PR reference for `run`"}

      ["help"] ->
        usage(opts.invoke)
        :ok

      ["--help"] ->
        usage(opts.invoke)
        :ok

      ["-h"] ->
        usage(opts.invoke)
        :ok

      ["help", _] ->
        usage(opts.invoke)
        :ok

      ["post", _pr_ref | _] ->
        usage(opts.invoke)
        {:error, "Invalid arguments"}

      ["run", _pr_ref | _] ->
        usage(opts.invoke)
        {:error, "Invalid arguments"}

      _ ->
        usage(opts.invoke)
        {:error, "Invalid arguments"}
    end
  end

  defp run_with_worktree_if_enabled(root, pr_ref, opts) do
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
  end

  defp run_in_root(root, pr_ref, opts) do
    with :ok <- ensure_clean_working_tree(root),
         {:ok, _checkout_ctx} <- checkout_pr_branch(root, pr_ref),
         {:ok, fetch_ctx} <- run_fetch(root, pr_ref),
         {:ok, apply_ctx} <- run_apply(root, fetch_ctx.tasks_json, opts),
         commit_ctx <- maybe_commit(root, apply_ctx.tasks_json, opts) do
      case commit_ctx do
        {:error, msg} ->
          {:error, msg}

        _ ->
          write_review_responses!(
            root,
            apply_ctx.tasks_json,
            apply_ctx.responses_md,
            apply_ctx.agent_last_message,
            apply_ctx.changed_files,
            commit_ctx
          )

          apply_ctx =
            Map.put(
              apply_ctx,
              :posting_metadata,
              detect_posting_metadata(root, apply_ctx.responses_md)
            )

          print_run_summary(root, fetch_ctx, apply_ctx, commit_ctx, opts)
          :ok
      end
    end
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
      #{invoke} [-C PATH|--repo PATH] [global opts] <pr-number|pr-url|owner/repo#number>
      #{invoke} [-C PATH|--repo PATH] [global opts] run <pr-number|pr-url|owner/repo#number>
      #{invoke} [-C PATH|--repo PATH] [global opts] post <pr-number|pr-url>

    Global opts:
      -C, --repo PATH         Target git repo (defaults to current directory).
      --model MODEL           Set the Codex model (same as `codex --model`).
      --reasoning-effort LVL  Set `reasoning_effort` via `codex --config` (e.g. low|medium|high).
      --commit                After a successful run, create a local git commit (never pushes).

      --worktree              (run only) Run inside a per-PR git worktree under `.worktrees/` (enables parallel PR sessions).
      --worktree-dir DIR      Override worktree base dir (default: `<repo_root>/.worktrees/agent_reviews`).

    Config files (optional):
      - ~/.agent_reviews.toml
      - <repo_root>/.agent_reviews.toml

    Env (optional):
      - AGENT_CMD   Agent executable (default: codex)
      - AGENT_ARGS  Extra args passed to the agent (shellwords)

    Notes:
      - `run` fetches review threads, runs the agent, and writes outputs under `#{@agent_dir}/` in the target repo.
      - `post` is optional and posts per-thread replies when the required JSON metadata block is present.
    """)
  end

  defp git_root(nil), do: git_root(".")
  defp git_root(path), do: AgentReviews.Repo.git_root(path)

  defp git_common_root(root), do: AgentReviews.Repo.git_common_root(root)

  def invoke_name, do: AgentReviews.Runtime.invoke_name()

  def ensure_cmd(cmd), do: AgentReviews.Runtime.ensure_cmd(cmd)

  # ----- Config loading (minimal TOML subset) -----
  defp load_effective_opts(root, opts), do: AgentReviews.Config.load_effective_opts(root, opts)

  defp effective_config_summary(opts, checkout?) do
    agent = Map.get(opts, :agent_cmd, "codex")
    agent_args = Map.get(opts, :agent_args, "")
    model = Map.get(opts, :model, nil) || "(default)"
    reasoning = Map.get(opts, :reasoning_effort, nil) || "(default)"

    args_str =
      if String.trim(to_string(agent_args)) == "", do: "(none)", else: to_string(agent_args)

    _checkout? = checkout?

    "agent_cmd=#{agent}, agent_args=#{args_str}, model=#{model}, reasoning=#{reasoning}"
  end

  defp ensure_repo_local_exclude(root), do: AgentReviews.Repo.ensure_repo_local_exclude(root)

  defp ensure_gh_authed, do: AgentReviews.Repo.ensure_gh_authed()

  defp checkout_pr_branch(root, pr_ref), do: AgentReviews.Repo.checkout_pr_branch(root, pr_ref)

  defp ensure_pr_worktree_root(root, pr_ref, opts),
    do: AgentReviews.Repo.ensure_pr_worktree_root(root, pr_ref, opts)

  defp ensure_agent_dir(root) do
    new_dir = Path.join(root, @agent_dir)
    old_dir = Path.join(root, ".agent")

    cond do
      File.dir?(new_dir) ->
        :ok

      File.dir?(old_dir) ->
        case File.rename(old_dir, new_dir) do
          :ok ->
            IO.puts(:stderr, "INFO: Renamed .agent/ -> #{@agent_dir}/")
            :ok

          _ ->
            File.mkdir_p!(new_dir)
            :ok
        end

      true ->
        File.mkdir_p!(new_dir)
        :ok
    end
  end

  defp run_fetch(root, pr_ref) do
    with :ok <- ensure_gh_authed(),
         {:ok, {owner, repo, number}} <- parse_pr_ref(pr_ref, root),
         :ok <- ensure_agent_dir(root) do
      agent_dir = Path.join(root, @agent_dir)
      tasks_json_path = Path.join(agent_dir, "tasks.json")
      review_threads_path = Path.join(agent_dir, "debug_review_threads.json")

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
           raw_pages: _raw_pages
         }} ->
          File.write!(
            tasks_json_path,
            tasks_json(pr_title, pr_url, head_ref, base_ref, head_sha, base_sha, tasks)
          )

          IO.puts("Wrote: #{tasks_json_path}")

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
             tasks_json: tasks_json_path
           }}

        {:error, msg, raw_pages} ->
          File.write!(review_threads_path, raw_pages)
          IO.puts(:stderr, "Wrote debug: #{review_threads_path}")
          {:error, msg}

        {:error, msg} ->
          {:error, msg}
      end
    end
  end

  defp run_apply(root, tasks_json_path, opts) do
    responses_md = Path.join([root, @agent_dir, "review_responses.md"])
    debug_log = Path.join([root, @agent_dir, "debug_agent_exec.log"])

    if not File.exists?(tasks_json_path) do
      {:error, "Missing #{tasks_json_path} (run: #{opts.invoke} <pr>)"}
    else
      agent_cmd_in = Map.get(opts, :agent_cmd, "codex")
      agent_args = shellwords(Map.get(opts, :agent_args, "")) ++ codex_args_from_opts(opts)
      agent_args = maybe_add_full_auto(agent_args, true)
      prompt = agent_prompt_template(opts, tasks_json_path, root)

      with :ok <- ensure_on_recorded_pr_head(root, tasks_json_path),
           {:ok, agent_cmd} <- resolve_agent_cmd(agent_cmd_in),
           :ok <- ensure_agent_noninteractive(agent_cmd) do
        if agent_cmd != agent_cmd_in do
          IO.puts(:stderr, "INFO: Using agent executable at #{agent_cmd}")
        end

        case run_agent_capture(root, agent_cmd, agent_args, prompt) do
          {:ok, %{last_message: last_message}} ->
            {:ok,
             %{
               tasks_json: tasks_json_path,
               responses_md: responses_md,
               agent_last_message: last_message,
               changed_files: changed_files(root)
             }}

          {:error, %{status: status, output: output, last_message: last_message}} ->
            File.write!(debug_log, output)
            IO.puts(:stderr, "Wrote debug: #{debug_log}")

            write_failure_review_responses!(
              root,
              tasks_json_path,
              responses_md,
              status,
              output,
              last_message
            )

            hint = codex_failure_hint(output)
            {:error, "Agent exited with status #{status} (see #{responses_md}).#{hint}"}
        end
      else
        {:error, msg} -> {:error, msg}
      end
    end
  end

  defp run_agent_capture(root, agent_cmd, agent_args, prompt) do
    tmp_last = tmp_path("agent_reviews_last_message", ".md")

    args =
      ["exec", "-C", Path.expand(root), "--output-last-message", tmp_last] ++ agent_args ++ ["-"]

    {out, status} =
      run_with_spinner("Running agent", fn ->
        System.cmd(agent_cmd, args, cd: root, stderr_to_stdout: true, input: prompt)
      end)

    last_message =
      case File.read(tmp_last) do
        {:ok, s} -> String.trim_trailing(s)
        _ -> ""
      end

    _ = File.rm(tmp_last)

    if status == 0 do
      {:ok, %{output: out, last_message: last_message}}
    else
      {:error, %{status: status, output: out, last_message: last_message}}
    end
  end

  defp tmp_path(prefix, suffix) do
    name = "#{prefix}-#{System.unique_integer([:positive])}#{suffix}"
    Path.join(System.tmp_dir!(), name)
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

    model_args ++ reasoning_args
  end

  defp toml_string(value) do
    escaped =
      value
      |> to_string()
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")

    ~s("#{escaped}")
  end

  defp print_run_summary(root, fetch_ctx, apply_ctx, commit_ctx, opts) do
    tasks_json = display_output_path(apply_ctx.tasks_json, root)
    responses = display_output_path(apply_ctx.responses_md, root)
    invoke = invoke_for_root(opts.invoke, root)

    IO.puts("\n== #{opts.invoke} run ==")
    IO.puts("Repo: #{Path.expand(root)}")
    IO.puts("PR: #{fetch_ctx.pr_url}")
    IO.puts("Title: #{fetch_ctx.pr_title}")
    IO.puts("Effective: #{effective_config_summary(opts, nil)}")
    IO.puts("Tasks: #{format_type_counts(fetch_ctx.tasks)}")
    IO.puts("Outputs:")
    IO.puts("  - `#{responses}`")
    IO.puts("  - `#{tasks_json}`")
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
    IO.puts("Effective: #{effective_config_summary(opts, nil)}")
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

  defp format_commit(%{enabled?: true, committed?: false, reason: :no_changes}),
    do: "enabled (no changes)"

  defp format_commit(%{enabled?: true, committed?: true, sha: sha}), do: "committed (#{sha})"
  defp format_commit(_), do: "unknown"

  defp resolve_agent_cmd(cmd) when is_binary(cmd) do
    cmd = String.trim(cmd)

    case System.find_executable(cmd) do
      nil ->
        {:error,
         "Codex CLI not found ('#{cmd}'). Install Codex CLI and/or set AGENT_CMD to the correct executable."}

      path ->
        # If this looks like an asdf shim and is failing with "No preset version", try to find a non-shim codex.
        {out, status} = System.cmd(path, ["--help"], stderr_to_stdout: true)

        if status != 0 and String.contains?(out, "No preset version installed for command codex") do
          case find_non_asdf_codex() do
            {:ok, other} ->
              {:ok, other}

            :error ->
              {:error,
               "Your shell is resolving `codex` to an asdf shim, but it isn't runnable here.\nRun `which codex` and either install Codex CLI properly or set `AGENT_CMD` to the real Codex executable path.\n\nOutput:\n#{out}"}
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

  defp codex_failure_hint(output) when is_binary(output) do
    cond do
      String.contains?(output, "stdin is not a terminal") ->
        "\nHint: your Codex invocation is running in interactive mode; ensure `codex exec` is available and being used."

      String.contains?(output, "Codex cannot access session files") or
          (String.contains?(output, "permission denied") and
             String.contains?(output, ".codex/sessions")) ->
        "\nHint: Codex cannot write to `~/.codex/sessions`. Fix ownership/permissions of `~/.codex` (Codex often suggests: `sudo chown -R $(whoami) ~/.codex`)."

      true ->
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
      tasks_json = Path.join([root, @agent_dir, "tasks.json"])

      cond do
        not File.exists?(responses) ->
          {:error, "Missing #{responses} (run: #{opts.invoke} <pr>)"}

        not File.exists?(tasks_json) ->
          {:error, "Missing #{tasks_json} (run: #{opts.invoke} <pr>)"}

        File.read!(responses) |> String.trim() == "" ->
          {:error, "#{responses} is empty"}

        true ->
          content = File.read!(responses)

          case extract_posting_metadata(content, root) do
            {:ok, %{"replies" => replies, "top_level_comment" => top_level_comment}} ->
              with {:ok, task_map} <- parse_tasks_json_for_posting(tasks_json) do
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
                    {:error,
                     "Posted #{posted} thread replies, but failed to post top-level comment.\n\n#{msg}"}

                  {{:error, msg1}, {:error, msg2}} ->
                    {:error, msg1 <> "\n\n" <> msg2}
                end
              else
                {:error, _} ->
                  {:error, "Failed to parse #{tasks_json} for posting validation."}
              end

            {:error, reason} ->
              {:error, reason}
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

  defp do_gh_graphql_pages(
         owner,
         repo,
         number,
         cursor,
         page_idx,
         max_pages,
         tasks_acc,
         raw_pages_acc,
         pr_meta
       )
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

        with {:ok, decoded} <- Jason.decode(out),
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
              do_gh_graphql_pages(
                owner,
                repo,
                number,
                end_cursor,
                page_idx + 1,
                max_pages,
                tasks,
                raw_pages_acc,
                pr_meta
              )

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
             "Malformed GitHub API response while extracting task fields (see #{@agent_dir}/debug_review_threads.json for debugging).",
             json_array(raw_pages_acc)}
        end

      {out, _} ->
        {:error, "Failed to fetch PR review threads via GitHub API.\n\nOutput:\n#{out}",
         json_array(raw_pages_acc || [])}
    end
  end

  defp do_gh_graphql_pages(
         _owner,
         _repo,
         _number,
         _cursor,
         _page_idx,
         _max_pages,
         tasks_acc,
         raw_pages_acc,
         pr_meta
       ) do
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
    case System.get_env("AGENT_REVIEWS_MAX_PAGES") do
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

              {prev, "previous",
               "Selected previous comment as the ask because the latest comment looks like an acknowledgement/resolution."}
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
           "Working tree has local changes. Please commit/stash/reset before running agent_reviews.\n\nOutput:\n#{out}"}
        end

      {out, _} ->
        {:error, "Failed to check git working tree status.\n\nOutput:\n#{out}"}
    end
  end

  defp ensure_on_recorded_pr_head(root, tasks_json_path) do
    with {:ok, tasks} <- read_tasks_json(tasks_json_path) do
      head_ref = Map.get(tasks, "pr_head_ref", "") |> to_string()
      head_sha = Map.get(tasks, "pr_head_sha", "") |> to_string()

      with :ok <- ensure_on_recorded_pr_branch_name(root, head_ref),
           :ok <- ensure_contains_pr_head_commit(root, head_ref, head_sha) do
        :ok
      end
    end
  end

  defp ensure_on_recorded_pr_branch_name(_root, ""), do: :ok

  defp ensure_on_recorded_pr_branch_name(root, head_ref) do
    case System.cmd("git", ["rev-parse", "--abbrev-ref", "HEAD"],
           cd: root,
           stderr_to_stdout: true
         ) do
      {out, 0} ->
        current = String.trim(out)

        if current == head_ref do
          :ok
        else
          IO.puts(
            :stderr,
            "WARN: You are on branch #{inspect(current)}, but this PR expects #{inspect(head_ref)}. Proceeding because HEAD-SHA validation is authoritative."
          )

          :ok
        end

      {out, _} ->
        {:error, "Failed to determine current git branch.\n\nOutput:\n#{out}"}
    end
  end

  defp ensure_contains_pr_head_commit(root, head_ref, head_sha),
    do: AgentReviews.Repo.ensure_contains_pr_head_commit(root, head_ref, head_sha)

  defp read_tasks_json(path) do
    with {:ok, content} <- File.read(path),
         {:ok, decoded} <- Jason.decode(content) do
      {:ok, decoded}
    else
      _ -> {:error, "Failed to parse #{path} (expected valid JSON)"}
    end
  end

  defp ensure_agent_noninteractive(agent_cmd) do
    {out, status} = System.cmd(agent_cmd, ["exec", "--help"], stderr_to_stdout: true)

    if status == 0 do
      :ok
    else
      {:error,
       "Your Codex CLI must support `codex exec` for non-interactive runs.\n\nTried: #{agent_cmd} exec --help\n\nOutput:\n#{out}\n\nHint: upgrade Codex CLI, or set AGENT_CMD to the correct Codex executable."}
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
      String.contains?(body, "?") or
          Enum.any?(["clarify", "why", "how", "what"], &String.contains?(lowered, &1)) ->
        "question"

      Enum.any?(["nit:", "minor", "style", "formatting"], &String.contains?(lowered, &1)) ->
        "nit"

      true ->
        "change"
    end
  end

  defp tasks_json(pr_title, pr_url, head_ref, base_ref, head_sha, base_sha, tasks) do
    doc = %{
      "pr_title" => pr_title,
      "pr_url" => pr_url,
      "pr_head_ref" => head_ref,
      "pr_base_ref" => base_ref,
      "pr_head_sha" => head_sha,
      "pr_base_sha" => base_sha,
      "tasks" => Enum.map(tasks || [], &task_to_json/1)
    }

    Jason.encode!(doc, pretty: true) <> "\n"
  end

  defp task_to_json(t) do
    %{
      "id" => Map.get(t, :id),
      "thread_id" => Map.get(t, :thread_id, "") || "",
      "path" => Map.get(t, :path, "") || "",
      "line" => Map.get(t, :line, nil),
      "diff_side" => Map.get(t, :diff_side, nil),
      "type" => Map.get(t, :type, "change") || "change",
      "author" => Map.get(t, :author, "unknown") || "unknown",
      "created_at" => Map.get(t, :created_at, "") || "",
      "comment_count" => Map.get(t, :comment_count, 0),
      "comment_total_count" => Map.get(t, :comment_total_count, nil),
      "comments_truncated" => Map.get(t, :comments_truncated, nil),
      "ask_selected" => Map.get(t, :ask_selected, "latest") || "latest",
      "ask_note" => Map.get(t, :ask_note, nil),
      "thread_opener" => comment_to_json(Map.get(t, :thread_opener, %{})),
      "latest_comment" => comment_to_json(Map.get(t, :latest_comment, %{})),
      "body" => Map.get(t, :body, "") || "",
      "all_comments" => all_comments_to_json(Map.get(t, :all_comments, nil))
    }
  end

  defp comment_to_json(nil), do: %{"author" => "unknown", "created_at" => "", "body" => ""}

  defp comment_to_json(map) when is_map(map) do
    %{
      "author" => Map.get(map, :author) || Map.get(map, "author") || "unknown",
      "created_at" => Map.get(map, :created_at) || Map.get(map, "created_at") || "",
      "body" => Map.get(map, :body) || Map.get(map, "body") || ""
    }
  end

  defp all_comments_to_json(nil), do: nil

  defp all_comments_to_json(comments) when is_list(comments) do
    Enum.map(comments, fn c ->
      %{
        "author" => Map.get(c, :author) || Map.get(c, "author") || "unknown",
        "created_at" => Map.get(c, :created_at) || Map.get(c, "created_at") || "",
        "body" => Map.get(c, :body) || Map.get(c, "body") || ""
      }
    end)
  end

  defp thread_suffix(thread_id), do: AgentReviews.Tasks.thread_suffix(thread_id)

  defp agent_prompt_template(_opts, tasks_json_path, root) do
    tasks_rel = Path.relative_to(tasks_json_path, root)

    """
    # PR Review Implementation Task

    Read `#{tasks_rel}` and implement/respond to each task systematically.

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

    - You MUST list **all** tasks from `#{tasks_rel}` in order (Task 1..N).
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
    - `thread_id` must come from `#{tasks_rel}` for that task.
    - `decision` must be `ANSWER` or `PUSHBACK`.
    - `top_level_comment` may be an empty string if you don't want a top-level PR comment.
    - The JSON block must be the final fenced ```json block at the end of the file (no other JSON blocks after it).
    """
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

  defp maybe_commit(_root, _tasks_json, %{commit?: false}), do: %{enabled?: false}

  defp maybe_commit(root, tasks_json, %{commit?: true}) do
    case System.cmd("git", ["status", "--porcelain"], cd: root, stderr_to_stdout: true) do
      {out, 0} ->
        if String.trim(out) == "" do
          %{enabled?: true, committed?: false, reason: :no_changes}
        else
          msg = default_commit_message(tasks_json)

          {add_out, add_status} =
            System.cmd("git", ["add", "-A"], cd: root, stderr_to_stdout: true)

          if add_status != 0 do
            {:error, "Failed to stage changes for commit.\n\nOutput:\n#{add_out}"}
          else
            {commit_out, commit_status} =
              System.cmd("git", ["commit", "-m", msg], cd: root, stderr_to_stdout: true)

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

  defp default_commit_message(tasks_json) do
    pr_url =
      case read_tasks_json(tasks_json) do
        {:ok, decoded} -> Map.get(decoded, "pr_url", "") |> to_string()
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

  defp parse_pr_ref(ref, root), do: AgentReviews.Repo.parse_pr_ref(ref, root)

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

  defp do_shellwords(<<"\\", rest::binary>>, acc, token, mode, false)
       when mode in [:normal, :double],
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

  defp do_shellwords(<<char::utf8, rest::binary>>, acc, token, :normal, false)
       when char in [?\s, ?\t, ?\n, ?\r] do
    if token == "" do
      do_shellwords(rest, acc, "", :normal, false)
    else
      do_shellwords(rest, [token | acc], "", :normal, false)
    end
  end

  defp do_shellwords(<<char::utf8, rest::binary>>, acc, token, mode, false),
    do: do_shellwords(rest, acc, token <> <<char::utf8>>, mode, false)

  # Posting metadata parsing (stdlib-only JSON parser)
  defp extract_posting_metadata(content, _root) do
    with {:ok, block} <- extract_final_json_fence(content),
         {:ok, decoded} <- parse_posting_metadata_json(block) do
      {:ok, decoded}
    else
      {:error, msg} -> {:error, msg}
    end
  rescue
    _ ->
      {:error,
       "Failed to parse JSON posting metadata block. Ensure the final fenced ```json block is valid JSON."}
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
           "Found a JSON code block, but posting metadata must be the FINAL fenced ```json block at the end of `#{@agent_dir}/review_responses.md`."}
        else
          {:error,
           "Could not find a JSON posting metadata code block (```json ... ```) in `#{@agent_dir}/review_responses.md`."}
        end
    end
  end

  defp parse_posting_metadata_json(json) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, %{"replies" => replies} = decoded} when is_list(replies) ->
        {:ok,
         %{
           "replies" => replies,
           "top_level_comment" => Map.get(decoded, "top_level_comment", "")
         }}

      {:ok, _} ->
        {:error,
         "Posting metadata JSON is valid, but it doesn't match the required shape: {replies: [...], top_level_comment: \"...\"}."}

      {:error, reason} ->
        {:error,
         "Failed to parse posting metadata JSON (#{Exception.message(reason)}). Ensure the final fenced ```json block is valid JSON."}
    end
  end

  defp post_thread_replies(root, replies, task_map) do
    {posted, failed, errors_log} =
      Enum.reduce(replies, {0, 0, nil}, fn reply, {posted, failed, errors_log} ->
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
              {posted + 1, failed, errors_log}

            {:error, out} ->
              errors_log = errors_log || Path.join([root, @agent_dir, "post_errors.log"])
              append_post_error!(errors_log, "task_id=#{task_id} thread_id=#{thread_id}", out)

              IO.puts(
                :stderr,
                "ERROR: Failed to post reply for task_id=#{task_id} (see #{errors_log})."
              )

              {posted, failed + 1, errors_log}
          end
        else
          {:ok, decision} ->
            IO.puts(
              :stderr,
              "WARN: Skipping reply with decision=#{inspect(decision)} (only ANSWER/PUSHBACK are posted)."
            )

            {posted, failed, errors_log}

          {:error, msg} ->
            IO.puts(:stderr, "WARN: Skipping malformed reply entry: #{msg}")
            {posted, failed, errors_log}

          false ->
            IO.puts(:stderr, "WARN: Skipping malformed reply entry.")
            {posted, failed, errors_log}
        end
      end)

    if failed == 0 do
      {:ok, posted}
    else
      errors_log = errors_log || Path.join([root, @agent_dir, "post_errors.log"])

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
        {:error, "Unknown task_id=#{task_id} (not found in #{@agent_dir}/tasks.json)"}

      ^thread_id ->
        :ok

      other ->
        {:error,
         "thread_id mismatch for task_id=#{task_id}: metadata has #{inspect(thread_id)}, but #{@agent_dir}/tasks.json has #{inspect(other)}"}
    end
  end

  defp parse_tasks_json_for_posting(path) do
    with {:ok, decoded} <- read_tasks_json(path),
         tasks when is_list(tasks) <- Map.get(decoded, "tasks", []) do
      thread_map =
        Enum.reduce(tasks, %{}, fn t, acc ->
          id = Map.get(t, "id")
          thread_id = Map.get(t, "thread_id")

          if is_integer(id) and is_binary(thread_id) and String.trim(thread_id) != "" do
            Map.put(acc, id, thread_id)
          else
            acc
          end
        end)

      {:ok, thread_map}
    else
      _ -> {:error, "Failed to parse #{path} for posting validation."}
    end
  end

  defp write_review_responses!(
         root,
         tasks_json_path,
         responses_md,
         agent_last_message,
         changed_files,
         commit_ctx
       ) do
    tasks_rel = Path.relative_to(tasks_json_path, root)
    tasks = tasks_list_for_wrapper(tasks_json_path)

    {pr_title, pr_url} =
      case read_tasks_json(tasks_json_path) do
        {:ok, decoded} ->
          {Map.get(decoded, "pr_title", "") |> to_string(), Map.get(decoded, "pr_url", "") |> to_string()}

        _ ->
          {"", ""}
      end

    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    changed =
      if changed_files == [] do
        "_No local changes detected._\n"
      else
        changed_files |> Enum.map(fn f -> "- `#{f}`\n" end) |> IO.iodata_to_binary()
      end

    raw =
      agent_last_message
      |> to_string()
      |> String.trim_trailing()
      |> Kernel.<>("\n")

    header =
      [
        "# PR Review Responses\n",
        "\n",
        "- Timestamp (UTC): ",
        now,
        "\n",
        if(pr_url != "", do: ["- PR: ", pr_url, "\n"], else: []),
        if(pr_title != "", do: ["- Title: ", pr_title, "\n"], else: []),
        "- Tasks: `",
        tasks_rel,
        "`\n",
        "- Commit: ",
        format_commit(commit_ctx),
        "\n",
        "\n",
        "## Task List\n",
        tasks,
        "\n",
        "## Working Tree\n",
        changed,
        "\n",
        "---\n",
        "\n",
        "## Agent Output (Last Message)\n",
        "\n"
      ]
      |> IO.iodata_to_binary()

    File.write!(responses_md, header <> raw)
    IO.puts("Wrote: #{responses_md}")
    :ok
  end

  defp write_failure_review_responses!(
         root,
         tasks_json_path,
         responses_md,
         status,
         _output,
         last_message
       ) do
    tasks_rel = Path.relative_to(tasks_json_path, root)
    tasks = tasks_list_for_wrapper(tasks_json_path)
    debug_log = Path.relative_to(Path.join([root, @agent_dir, "debug_agent_exec.log"]), root)

    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    last =
      last_message
      |> to_string()
      |> String.trim_trailing()

    header =
      [
        "# PR Review Responses (FAILED)\n",
        "\n",
        "- Timestamp (UTC): ",
        now,
        "\n",
        "- Tasks: `",
        tasks_rel,
        "`\n",
        "- Agent exit status: ",
        to_string(status),
        "\n",
        "- Debug: `",
        debug_log,
        "`\n",
        "\n",
        "## Task List\n",
        tasks,
        "\n"
      ]
      |> IO.iodata_to_binary()

    body =
      if String.trim(last) == "" do
        "\n## Agent Last Message\n\n_(empty)_\n"
      else
        "\n## Agent Last Message\n\n" <> last <> "\n"
      end

    File.write!(responses_md, header <> body)
    IO.puts("Wrote: #{responses_md}")
    :ok
  end

  defp tasks_list_for_wrapper(tasks_json_path) do
    with {:ok, decoded} <- read_tasks_json(tasks_json_path),
         tasks when is_list(tasks) <- Map.get(decoded, "tasks", []) do
      tasks =
        tasks
        |> Enum.sort_by(fn t -> Map.get(t, "id", 0) end)

      if tasks == [] do
        "_No tasks found._\n"
      else
        tasks
        |> Enum.map(fn t ->
          id = Map.get(t, "id", 0)
          path = Map.get(t, "path", "") |> to_string()
          line = Map.get(t, "line", nil)
          type = Map.get(t, "type", "change") |> to_string()
          author = Map.get(t, "author", "unknown") |> to_string()
          thread_id = Map.get(t, "thread_id", "") |> to_string()

          loc =
            if is_integer(line) do
              "#{path}:#{line}"
            else
              path
            end

          suffix = thread_suffix(thread_id)

          comments =
            case Map.get(t, "comment_total_count") do
              n when is_integer(n) and n > 0 ->
                truncated? = Map.get(t, "comments_truncated", false) == true
                shown = Map.get(t, "comment_count", 0)

                if truncated? do
                  "comments: last #{shown} of #{n}"
                else
                  "comments: #{n}"
                end

              _ ->
                "comments: #{Map.get(t, "comment_count", 0)}"
            end

          ask_selected = Map.get(t, "ask_selected", "latest") |> to_string()
          ask_note = Map.get(t, "ask_note", nil)
          ask = Map.get(t, "body", "") |> to_string()
          ask_excerpt = wrapper_excerpt(ask)

          [
            "- Task ",
            Integer.to_string(id),
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
            if(is_binary(ask_note) and String.trim(ask_note) != "",
              do: ["  - Note: ", wrapper_excerpt(ask_note), "\n"],
              else: []
            )
          ]
        end)
      end
    else
      _ -> "_No tasks found._\n"
    end
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
    File.mkdir_p!(Path.dirname(errors_log))
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

    with_temp_file("agent_reviews_thread_reply", ".md", body, fn body_path ->
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

      case System.cmd("gh", args, cd: root, stderr_to_stdout: true) do
        {_out, 0} -> :ok
        {out, _} -> {:error, out}
      end
    end)
  end

  defp maybe_post_top_level_comment(root, pr_ref, top_level_comment)
       when is_binary(top_level_comment) do
    if String.trim(top_level_comment) == "" do
      :ok
    else
      with_temp_file("agent_reviews_top_level_comment", ".md", top_level_comment, fn path ->
        case System.cmd("gh", ["pr", "comment", pr_ref, "--body-file", path],
               cd: root,
               stderr_to_stdout: true
             ) do
          {_out, 0} -> :ok
          {out, _} -> {:error, "Failed to post top-level PR comment.\n\nOutput:\n#{out}"}
        end
      end)
    end
  end

  defp maybe_post_top_level_comment(_root, _pr_ref, _), do: :ok

  defp with_temp_file(prefix, suffix, content, fun) when is_function(fun, 1) do
    path = tmp_path(prefix, suffix)
    File.write!(path, content)

    try do
      fun.(path)
    after
      _ = File.rm(path)
    end
  end
end
