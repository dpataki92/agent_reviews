defmodule AgentReviews.CLI do
  @agent_dir ".agent_review"
  @agent_timeout_ms 2 * 60 * 60 * 1000

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
        worktree_dir: nil,
        additional_comment: nil
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

  defp parse_opts(["--comment", comment | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | additional_comment: comment}, rest_rev)

  defp parse_opts(["-m", comment | rest], opts, rest_rev),
    do: parse_opts(rest, %{opts | additional_comment: comment}, rest_rev)

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
          {:error,
           "--worktree is only supported for `run` (cd into the worktree and run `post` there)."}
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
         {:ok, checkout_ctx} <- checkout_pr_branch(root, pr_ref) do
      pr_number = Map.get(checkout_ctx, :pr_number)
      state_root = state_root(opts, root)

      with_pr_lock(state_root, pr_number, fn ->
        with {:ok, fetch_ctx} <- run_fetch(root, pr_ref),
             {:ok, tasks_doc} <- read_tasks_json(fetch_ctx.tasks_json) do
          {:ok, prev_state} = load_pr_state(state_root, pr_number)

          diff = diff_since_last_run(tasks_doc, prev_state)
          selection = select_tasks_for_agent(tasks_doc, diff, prev_state)

          responses_md = Path.join([root, @agent_dir, "review_responses.md"])

          apply_ctx =
            case selection.agent_tasks_doc do
              nil ->
                {:ok,
                 %{
                   tasks_json: fetch_ctx.tasks_json,
                   responses_md: responses_md,
                   agent_last_message: "",
                   agent_ran?: false,
                   changed_files: changed_files(root)
                 }}

              agent_tasks_doc ->
                content = Jason.encode!(agent_tasks_doc, pretty: true) <> "\n"

                with_temp_file("agent_reviews_tasks", ".json", content, fn agent_tasks_path ->
                  run_apply(root, fetch_ctx.tasks_json, agent_tasks_path, opts)
                end)
            end

          with {:ok, apply_ctx} <- apply_ctx do
            commit_ctx = maybe_commit(root, apply_ctx.tasks_json, opts)

            case commit_ctx do
              {:error, msg} ->
                {:error, msg}

              _ ->
                {agent_body, agent_meta} =
                  if apply_ctx.agent_ran? do
                    split_agent_last_message(apply_ctx.agent_last_message)
                  else
                    {"", {:ok, %{"replies" => [], "top_level_comment" => ""}}}
                  end

                {carried_replies, carried_notes} =
                  carried_forward_replies(tasks_doc, diff, prev_state)

                final_meta =
                  merge_posting_metadata(tasks_doc, carried_replies, agent_meta, carried_notes)

                write_review_responses!(
                  root,
                  tasks_doc,
                  apply_ctx.tasks_json,
                  apply_ctx.responses_md,
                  apply_ctx.agent_ran?,
                  agent_body,
                  apply_ctx.changed_files,
                  commit_ctx,
                  diff,
                  prev_state,
                  selection,
                  carried_replies,
                  carried_notes,
                  agent_meta,
                  final_meta
                )

                posting_metadata = detect_posting_metadata(root, apply_ctx.responses_md)

                warn_state_write_error(
                  update_pr_state_after_run(
                    state_root,
                    pr_number,
                    tasks_doc,
                    prev_state,
                    agent_meta,
                    selection,
                    diff,
                    final_meta,
                    posting_metadata
                  ),
                  "Failed to persist run history"
                )

                apply_ctx = Map.put(apply_ctx, :posting_metadata, posting_metadata)
                print_run_summary(root, fetch_ctx, apply_ctx, commit_ctx, opts)
                :ok
            end
          end
        end
      end)
    end
  end

  defp halt_on_error(:ok), do: :ok
  defp halt_on_error({:ok, _}), do: :ok

  defp halt_on_error({:error, msg}) when is_binary(msg) do
    IO.puts(:stderr, "ERROR: #{msg}")
    System.halt(1)
  end

  defp warn_state_write_error(:ok, _context), do: :ok

  defp warn_state_write_error({:error, msg}, context) do
    IO.puts(
      :stderr,
      "WARN: #{context}: #{msg}\nWARN: Rerunning `post` may repost already-posted replies."
    )

    :ok
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
      -m, --comment TEXT      Add additional context/instructions for this specific run only.

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

  defp state_root(opts, root) do
    Map.get(opts, :common_root) || root
  end

  defp pr_state_path(state_root, pr_number) when is_integer(pr_number) do
    Path.join([state_root, @agent_dir, "state", "pr-#{pr_number}.json"])
  end

  defp pr_state_path(_state_root, _), do: nil

  defp load_pr_state(_state_root, nil), do: {:ok, nil}

  defp load_pr_state(state_root, pr_number) when is_integer(pr_number) do
    path = pr_state_path(state_root, pr_number)

    if is_binary(path) and File.exists?(path) do
      with {:ok, content} <- File.read(path),
           {:ok, decoded} <- Jason.decode(content) do
        {:ok, decoded}
      else
        _ -> {:ok, nil}
      end
    else
      {:ok, nil}
    end
  end

  defp write_pr_state(_state_root, nil, _state), do: :ok

  defp write_pr_state(state_root, pr_number, state)
       when is_integer(pr_number) and is_map(state) do
    with :ok <- ensure_agent_dir(state_root) do
      path = pr_state_path(state_root, pr_number)
      dir = Path.dirname(path)

      with :ok <- mkdir_p(dir) do
        encoded = Jason.encode!(state, pretty: true) <> "\n"
        tmp = path <> ".tmp." <> tmp_token()

        with :ok <- write_file(tmp, encoded) do
          case File.rename(tmp, path) do
            :ok ->
              :ok

            {:error, _} ->
              _ = File.rm(tmp)
              write_file(path, encoded)
          end
        end
      end
    end
  end

  defp mark_replies_posted(_state_root, nil, _thread_ids), do: :ok
  defp mark_replies_posted(_state_root, _pr_number, []), do: :ok

  defp mark_replies_posted(state_root, pr_number, thread_ids)
       when is_integer(pr_number) and is_list(thread_ids) do
    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    case load_pr_state(state_root, pr_number) do
      {:ok, state} when is_map(state) ->
        threads = map_get_map(state, "threads")

        threads =
          Enum.reduce(thread_ids, threads, fn tid, acc ->
            tid = to_string(tid) |> String.trim()

            if tid == "" do
              acc
            else
              entry = Map.get(acc, tid, %{})
              decision = Map.get(entry, "decision", "") |> to_string() |> String.trim()
              body = Map.get(entry, "reply_body", "") |> to_string() |> String.trim()

              if decision in ["ANSWER", "PUSHBACK"] and body != "" do
                Map.put(acc, tid, Map.put(entry, "reply_posted_at", now))
              else
                acc
              end
            end
          end)

        state = Map.put(state, "threads", threads)
        write_pr_state(state_root, pr_number, state)

      _ ->
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

  defp run_apply(root, recorded_tasks_json_path, agent_tasks_json_path, opts) do
    responses_md = Path.join([root, @agent_dir, "review_responses.md"])
    debug_log = Path.join([root, @agent_dir, "debug_agent_exec.log"])

    cond do
      not File.exists?(recorded_tasks_json_path) ->
        {:error, "Missing #{recorded_tasks_json_path} (run: #{opts.invoke} <pr>)"}

      not File.exists?(agent_tasks_json_path) ->
        {:error, "Missing #{agent_tasks_json_path} (internal agent tasks file)"}

      true ->
        agent_cmd_in = Map.get(opts, :agent_cmd, "codex")

        with {:ok, split_args} <- split_agent_args(Map.get(opts, :agent_args, "")),
             prompt <- agent_prompt_template(opts, agent_tasks_json_path, root),
             :ok <- ensure_on_recorded_pr_head(root, recorded_tasks_json_path),
             {:ok, agent_cmd} <- resolve_agent_cmd(agent_cmd_in),
             {:ok, agent_type} <- AgentReviews.AgentAdapter.detect_agent_type(agent_cmd),
             :ok <-
               AgentReviews.AgentAdapter.validate_noninteractive_support(agent_cmd, agent_type) do
          if agent_cmd != agent_cmd_in do
            IO.puts(:stderr, "INFO: Using agent executable at #{agent_cmd}")
          end

          case run_agent_capture(root, agent_cmd, agent_type, split_args, opts, prompt) do
            {:ok, %{last_message: last_message}} ->
              {:ok,
               %{
                 tasks_json: recorded_tasks_json_path,
                 responses_md: responses_md,
                 agent_last_message: last_message,
                 agent_ran?: true,
                 changed_files: changed_files(root)
               }}

            {:error, %{status: status, output: output, last_message: last_message}} ->
              File.write!(debug_log, output)
              IO.puts(:stderr, "Wrote debug: #{debug_log}")

              write_failure_review_responses!(
                root,
                recorded_tasks_json_path,
                responses_md,
                status,
                output,
                last_message
              )

              hint = AgentReviews.AgentAdapter.failure_hint(agent_type, output)
              {:error, "Agent exited with status #{status} (see #{responses_md}).#{hint}"}
          end
        else
          {:error, :unknown} ->
            {:error,
             "Unknown agent type for AGENT_CMD=#{inspect(agent_cmd_in)} (supported: codex, claude).\nIf you’re using Claude Code, set `AGENT_CMD=claude`.\nIf you’re using Codex, set `AGENT_CMD=codex`."}

          {:error, msg} ->
            {:error, msg}
        end
    end
  end

  defp split_agent_args(raw) do
    raw = raw |> to_string() |> String.trim()

    if raw == "" do
      {:ok, []}
    else
      try do
        {:ok, OptionParser.split(raw)}
      rescue
        e in OptionParser.ParseError ->
          {:error, "Invalid AGENT_ARGS: #{Exception.message(e)}"}
      end
    end
  end

  defp run_agent_capture(root, agent_cmd, agent_type, agent_args, opts, prompt) do
    tmp_last =
      case agent_type do
        :codex -> tmp_path("agent_reviews_last_message", ".md")
        _ -> nil
      end

    tmp_prompt = tmp_path("agent_reviews_prompt", ".md")

    with {:ok, args} <-
           AgentReviews.AgentAdapter.build_exec_args(
             agent_type,
             root,
             tmp_last,
             agent_args,
             opts
           ),
         :ok <- File.write(tmp_prompt, prompt) do
      {out, status} =
        run_with_spinner("Running agent", fn ->
          cmd =
            ["exec", sh_single_quote(agent_cmd)]
            |> Kernel.++(Enum.map(args, &sh_single_quote/1))
            |> Enum.join(" ")
            |> Kernel.<>(" < ")
            |> Kernel.<>(sh_single_quote(tmp_prompt))

          System.cmd("sh", ["-c", cmd], cd: root, stderr_to_stdout: true)
        end)

      {last_message, cleanup_tmp?, status} =
        case agent_type do
          :codex ->
            msg =
              case File.read(tmp_last) do
                {:ok, s} -> String.trim_trailing(s)
                _ -> ""
              end

            {msg, true, status}

          :claude ->
            trimmed = String.trim_trailing(out)

            case AgentReviews.AgentAdapter.claude_result_from_output(trimmed) do
              {:ok, %{result: result, is_error?: true}} ->
                {String.trim_trailing(result), false, if(status == 0, do: 1, else: status)}

              {:ok, %{result: result, is_error?: false}} ->
                {String.trim_trailing(result), false, status}

              :error ->
                {trimmed, false, status}
            end
        end

      if cleanup_tmp? and is_binary(tmp_last), do: _ = File.rm(tmp_last)
      _ = File.rm(tmp_prompt)

      if status == 0 do
        {:ok, %{output: out, last_message: last_message}}
      else
        {:error, %{status: status, output: out, last_message: last_message}}
      end
    end
  end

  defp tmp_path(prefix, suffix) do
    name = "#{prefix}-#{tmp_token()}#{suffix}"
    Path.join(System.tmp_dir!(), name)
  end

  defp tmp_token do
    :crypto.strong_rand_bytes(12)
    |> Base.url_encode64(padding: false)
  end

  defp write_file(path, content) when is_binary(path) and is_binary(content) do
    case File.write(path, content) do
      :ok -> :ok
      {:error, reason} -> {:error, "Failed to write #{path} (#{inspect(reason)})"}
    end
  end

  defp mkdir_p(dir) when is_binary(dir) do
    case File.mkdir_p(dir) do
      :ok -> :ok
      {:error, reason} -> {:error, "Failed to create directory #{dir} (#{inspect(reason)})"}
    end
  end

  defp map_get_any(map, key1, key2, default \\ nil)
       when is_map(map) and (is_atom(key1) or is_binary(key1)) and is_binary(key2) do
    case Map.get(map, key1, nil) do
      nil -> Map.get(map, key2, default)
      v -> v
    end
  end

  defp sh_single_quote(value) do
    value = to_string(value)
    "'" <> String.replace(value, "'", "'\\''") <> "'"
  end

  defp split_lines_trim_end(text) when is_binary(text) do
    text
    |> String.split(["\r\n", "\n", "\r"], trim: false)
    |> Enum.reverse()
    |> Enum.drop_while(fn l -> String.trim(l) == "" end)
    |> Enum.reverse()
  end

  defp has_any_json_fence?(lines) when is_list(lines) do
    Enum.any?(lines, fn line ->
      line = to_string(line) |> String.trim()
      Regex.match?(~r/^```(json|jsonc)\b/i, line)
    end)
  end

  defp extract_final_json_fence_parts([]), do: {:error, :empty}

  defp extract_final_json_fence_parts(lines) when is_list(lines) do
    last_line = List.last(lines) |> to_string() |> String.trim()

    if last_line != "```" do
      {:error, :missing_close}
    else
      close_idx = length(lines) - 1

      open_idx =
        (close_idx - 1)..0//-1
        |> Enum.find(fn i ->
          line = Enum.at(lines, i) |> to_string() |> String.trim()
          Regex.match?(~r/^```(json|jsonc)$/i, line)
        end)

      if is_integer(open_idx) do
        before =
          lines
          |> Enum.take(open_idx)
          |> Enum.join("\n")
          |> String.trim_trailing()

        json =
          lines
          |> Enum.slice(open_idx + 1, close_idx - open_idx - 1)
          |> Enum.join("\n")
          |> String.trim()

        {:ok, %{before: before, json: json}}
      else
        {:error, :missing_open}
      end
    end
  end

  defp tail_excerpt(lines, n) when is_list(lines) and is_integer(n) and n > 0 do
    lines
    |> Enum.take(-n)
    |> Enum.join("\n")
    |> String.trim_trailing()
  end

  defp with_pr_lock(state_root, pr_number, fun)
       when is_integer(pr_number) and is_function(fun, 0) do
    lock_dir = Path.join([state_root, @agent_dir, "state", "locks"])
    lock_path = Path.join(lock_dir, "pr-#{pr_number}.lock")

    with :ok <- mkdir_p(lock_dir),
         {:ok, io} <- File.open(lock_path, [:write, :exclusive]) do
      now =
        DateTime.utc_now()
        |> DateTime.to_iso8601()

      _ = IO.write(io, "pid=#{System.pid()} at=#{now}\n")

      try do
        fun.()
      after
        _ = File.close(io)
        _ = File.rm(lock_path)
      end
    else
      {:error, :eexist} ->
        {:error,
         "Another `agent_reviews` process appears to be running for PR #{pr_number}.\n\nLock: #{lock_path}\n\nIf you are sure nothing is running, delete the lock file and retry."}

      {:error, msg} when is_binary(msg) ->
        {:error, msg}

      {:error, reason} ->
        {:error, "Failed to acquire PR lock #{lock_path} (#{inspect(reason)})."}
    end
  end

  defp run_with_spinner(label, fun) when is_function(fun, 0) do
    if spinner_enabled?() do
      frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
      task = Task.async(fun)

      started_ms = System.monotonic_time(:millisecond)
      result = await_with_spinner(task, label, frames, 0, started_ms, @agent_timeout_ms)

      case result do
        {:error, {:timeout, timeout_ms}} ->
          mins = Float.round(timeout_ms / 60_000, 1)
          IO.write("\r#{label}... timed out after #{mins} minutes\n")
          {"ERROR: Agent timed out after #{mins} minutes.\n", 124}

        _ ->
          IO.write("\r#{label}... done\n")
          result
      end
    else
      IO.puts("#{label}...")
      fun.()
    end
  end

  defp await_with_spinner(task, label, frames, idx, started_ms, timeout_ms) do
    case Task.yield(task, 120) do
      {:ok, result} ->
        result

      nil ->
        elapsed = System.monotonic_time(:millisecond) - started_ms

        if elapsed >= timeout_ms do
          _ = Task.shutdown(task, :brutal_kill)
          {:error, {:timeout, timeout_ms}}
        else
          frame = Enum.at(frames, rem(idx, length(frames)))
          IO.write("\r#{label}... #{frame}")
          await_with_spinner(task, label, frames, idx + 1, started_ms, timeout_ms)
        end
    end
  end

  defp spinner_enabled? do
    IO.ANSI.enabled?() and System.get_env("TERM", "dumb") != "dumb"
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
         "Agent CLI not found ('#{cmd}'). Install Codex (`codex`) or Claude Code (`claude`), or set AGENT_CMD to the correct executable."}

      path ->
        {out, status} = System.cmd(path, ["--help"], stderr_to_stdout: true)

        if status != 0 and String.contains?(out, "No preset version installed for command codex") do
          case find_non_asdf_codex() do
            {:ok, other} ->
              {:ok, other}

            :error ->
              {:error,
               "Your shell is resolving `codex` to an asdf shim, but it isn't runnable here.\nRun `which codex` and either install Codex CLI properly or set AGENT_CMD to the real Codex executable path.\n\nOutput:\n#{out}"}
          end
        else
          {:ok, path}
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

  defp run_post(root, pr_ref, opts) do
    with :ok <- ensure_gh_authed(),
         :ok <- ensure_cmd("gh"),
         {:ok, {_owner, _repo, pr_number}} <- parse_pr_ref(pr_ref, root) do
      with_pr_lock(state_root(opts, root), pr_number, fn ->
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
                    {{:ok, posted, posted_thread_ids}, :ok} ->
                      warn_state_write_error(
                        mark_replies_posted(
                          state_root(opts, root),
                          pr_number,
                          posted_thread_ids
                        ),
                        "Failed to persist posted-replies state"
                      )

                      {:ok,
                       %{
                         posted_replies: posted,
                         top_level_posted?: String.trim(to_string(top_level_comment)) != ""
                       }}

                    {{:error, msg, posted_thread_ids}, :ok} ->
                      warn_state_write_error(
                        mark_replies_posted(
                          state_root(opts, root),
                          pr_number,
                          posted_thread_ids
                        ),
                        "Failed to persist posted-replies state"
                      )

                      {:error, msg}

                    {{:ok, posted, posted_thread_ids}, {:error, msg}} ->
                      warn_state_write_error(
                        mark_replies_posted(
                          state_root(opts, root),
                          pr_number,
                          posted_thread_ids
                        ),
                        "Failed to persist posted-replies state"
                      )

                      {:error,
                       "Posted #{posted} thread replies, but failed to post top-level comment.\n\n#{msg}"}

                    {{:error, msg1, posted_thread_ids}, {:error, msg2}} ->
                      warn_state_write_error(
                        mark_replies_posted(
                          state_root(opts, root),
                          pr_number,
                          posted_thread_ids
                        ),
                        "Failed to persist posted-replies state"
                      )

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
      end)
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

  defp diff_since_last_run(tasks_doc, prev_state) when is_map(tasks_doc) do
    tasks = Map.get(tasks_doc, "tasks", []) || []

    current_thread_ids =
      tasks
      |> Enum.map(&task_thread_id/1)
      |> Enum.reject(&(&1 == ""))
      |> MapSet.new()

    prev_open =
      prev_state
      |> map_get_list("last_open_thread_ids")
      |> Enum.map(&to_string/1)
      |> Enum.reject(&(&1 == ""))
      |> MapSet.new()

    prev_threads = prev_state |> map_get_map("threads")

    new_ids = MapSet.difference(current_thread_ids, prev_open)
    resolved_ids = MapSet.difference(prev_open, current_thread_ids)
    common_ids = MapSet.intersection(current_thread_ids, prev_open)

    updated_ids =
      Enum.reduce(common_ids, MapSet.new(), fn tid, acc ->
        prev_fp =
          prev_threads
          |> Map.get(tid, %{})
          |> Map.get("fingerprint", "")
          |> to_string()

        current_fp =
          tasks
          |> Enum.find(fn t -> task_thread_id(t) == tid end)
          |> then(fn
            nil -> ""
            t -> task_fingerprint(t)
          end)

        if prev_fp != "" and current_fp != "" and prev_fp != current_fp do
          MapSet.put(acc, tid)
        else
          acc
        end
      end)

    carried_ids = MapSet.difference(common_ids, updated_ids)

    carried_needs_attention_ids =
      Enum.reduce(carried_ids, MapSet.new(), fn tid, acc ->
        decision =
          prev_threads
          |> Map.get(tid, %{})
          |> Map.get("decision", nil)

        decision = if is_binary(decision), do: String.trim(decision), else: nil

        if decision in ["ACCEPT", "ANSWER", "PUSHBACK"] do
          acc
        else
          MapSet.put(acc, tid)
        end
      end)

    %{
      prev_run_at: map_get_string(prev_state, "last_run_at"),
      current_open_ids: MapSet.to_list(current_thread_ids),
      prev_open_ids: MapSet.to_list(prev_open),
      new_ids: MapSet.to_list(new_ids),
      updated_ids: MapSet.to_list(updated_ids),
      carried_ids: MapSet.to_list(carried_ids),
      carried_needs_attention_ids: MapSet.to_list(carried_needs_attention_ids),
      resolved_ids: MapSet.to_list(resolved_ids)
    }
  end

  defp select_tasks_for_agent(tasks_doc, diff, prev_state) when is_map(tasks_doc) do
    tasks = Map.get(tasks_doc, "tasks", []) || []

    if tasks == [] do
      %{agent_tasks: [], agent_tasks_doc: nil, skipped_thread_ids: [], handled_thread_ids: []}
    else
      prev_run_at = map_get_string(prev_state, "last_run_at")

      {agent_thread_ids, handled_thread_ids} =
        if prev_run_at == "" do
          {tasks |> Enum.map(&task_thread_id/1) |> Enum.reject(&(&1 == "")), []}
        else
          to_handle =
            MapSet.new(diff.new_ids ++ diff.updated_ids ++ diff.carried_needs_attention_ids)

          handled = MapSet.new(diff.carried_ids -- diff.carried_needs_attention_ids)

          {MapSet.to_list(to_handle), MapSet.to_list(handled)}
        end

      agent_thread_set = MapSet.new(agent_thread_ids)

      agent_tasks =
        tasks
        |> Enum.filter(fn t -> MapSet.member?(agent_thread_set, task_thread_id(t)) end)

      enriched =
        if prev_state do
          threads = map_get_map(prev_state, "threads")

          Enum.map(agent_tasks, fn t ->
            tid = task_thread_id(t)
            entry = Map.get(threads, tid, %{})

            t
            |> Map.put("prior_decision", Map.get(entry, "decision", nil))
            |> Map.put("prior_decision_at", Map.get(entry, "decision_at", nil))
            |> Map.put("prior_reply_body", Map.get(entry, "reply_body", nil))
            |> Map.put("prior_reply_posted_at", Map.get(entry, "reply_posted_at", nil))
          end)
        else
          agent_tasks
        end

      agent_tasks_doc =
        tasks_doc
        |> Map.put("tasks", enriched)
        |> Map.put("previous_run_at", map_get_string(prev_state, "last_run_at"))

      skipped_thread_ids =
        tasks
        |> Enum.map(&task_thread_id/1)
        |> Enum.reject(&(&1 == ""))
        |> Enum.reject(fn tid -> MapSet.member?(agent_thread_set, tid) end)

      %{
        agent_tasks: enriched,
        agent_tasks_doc: if(enriched == [], do: nil, else: agent_tasks_doc),
        skipped_thread_ids: skipped_thread_ids,
        handled_thread_ids: handled_thread_ids
      }
    end
  end

  defp carried_forward_replies(tasks_doc, diff, prev_state) when is_map(tasks_doc) do
    tasks = Map.get(tasks_doc, "tasks", []) || []
    by_tid = Map.new(tasks, fn t -> {task_thread_id(t), t} end)

    threads = prev_state |> map_get_map("threads")
    carried_set = MapSet.new(diff.carried_ids)

    replies =
      carried_set
      |> Enum.flat_map(fn tid ->
        entry = Map.get(threads, tid, %{})
        decision = Map.get(entry, "decision", "") |> to_string() |> String.trim()
        body = Map.get(entry, "reply_body", "") |> to_string()
        posted_at = Map.get(entry, "reply_posted_at", nil)

        cond do
          decision not in ["ANSWER", "PUSHBACK"] ->
            []

          String.trim(body) == "" ->
            []

          is_binary(posted_at) and String.trim(posted_at) != "" ->
            []

          not Map.has_key?(by_tid, tid) ->
            []

          true ->
            [
              %{
                "thread_id" => tid,
                "decision" => decision,
                "body" => body,
                "decision_at" => Map.get(entry, "decision_at", nil)
              }
            ]
        end
      end)

    notes =
      carried_set
      |> Enum.reduce(%{}, fn tid, acc ->
        entry = Map.get(threads, tid, %{})

        Map.put(acc, tid, %{
          "decision" => Map.get(entry, "decision", nil),
          "decision_at" => Map.get(entry, "decision_at", nil),
          "reply_posted_at" => Map.get(entry, "reply_posted_at", nil),
          "last_task_id" => Map.get(entry, "last_task_id", nil),
          "last_loc" => Map.get(entry, "last_loc", nil),
          "ask_excerpt" => Map.get(entry, "ask_excerpt", nil)
        })
      end)

    {replies, notes}
  end

  defp split_agent_last_message(message) when is_binary(message) do
    message = to_string(message)
    lines = split_lines_trim_end(message)
    has_any_json_fence? = has_any_json_fence?(lines)

    case extract_final_json_fence_parts(lines) do
      {:ok, %{before: before, json: json}} ->
        case parse_posting_metadata_json(json) do
          {:ok, decoded} ->
            {before, {:ok, decoded}}

          {:error, reason} ->
            {message, {:error, reason}}
        end

      {:error, kind} ->
        tail = tail_excerpt(lines, 18)

        msg =
          case {kind, has_any_json_fence?} do
            {:empty, _} ->
              "Missing final posting metadata JSON block."

            {:missing_close, true} ->
              "Found a ```json block, but it is missing the closing ``` fence at the very end of the message."

            {:missing_close, false} ->
              "Missing final posting metadata JSON block."

            {:missing_open, true} ->
              "Found a closing ``` fence at the end, but could not find a matching ```json opener."

            {:missing_open, false} ->
              "Missing final posting metadata JSON block."
          end

        extra =
          if tail == "" do
            ""
          else
            "\n\nLast lines seen:\n\n```\n#{tail}\n```"
          end

        {message, {:error, msg <> extra}}
    end
  end

  defp merge_posting_metadata(tasks_doc, carried_replies, agent_meta, carried_notes)
       when is_map(tasks_doc) do
    tasks = Map.get(tasks_doc, "tasks", []) || []
    by_tid = Map.new(tasks, fn t -> {task_thread_id(t), t} end)

    carried =
      carried_replies
      |> Enum.map(fn r -> {Map.get(r, "thread_id", "") |> to_string(), r} end)
      |> Enum.reject(fn {tid, _} -> tid == "" end)
      |> Map.new()

    agent =
      case agent_meta do
        {:ok, %{"replies" => replies}} when is_list(replies) -> replies
        _ -> []
      end
      |> Enum.map(fn r -> {Map.get(r, "thread_id", "") |> to_string(), r} end)
      |> Enum.reject(fn {tid, _} -> tid == "" end)
      |> Map.new()

    merged =
      carried
      |> Map.merge(agent)
      |> Enum.flat_map(fn {tid, r} ->
        task = Map.get(by_tid, tid)

        with true <- is_map(task),
             id when is_integer(id) <- Map.get(task, "id"),
             decision when is_binary(decision) <- Map.get(r, "decision"),
             true <- String.trim(decision) != "",
             body when is_binary(body) <- Map.get(r, "body"),
             body_trim <- String.trim(body),
             true <- body_trim != "" do
          [
            %{
              "task_id" => id,
              "thread_id" => tid,
              "decision" => decision,
              "body" => body_trim
            }
          ]
        else
          _ -> []
        end
      end)
      |> Enum.sort_by(fn r -> Map.get(r, "task_id", 0) end)

    top_level_comment =
      case agent_meta do
        {:ok, %{"top_level_comment" => tlc}} when is_binary(tlc) -> tlc
        _ -> ""
      end

    _carried_notes = carried_notes

    %{"replies" => merged, "top_level_comment" => top_level_comment}
  end

  defp task_thread_id(task) when is_map(task),
    do: Map.get(task, "thread_id", "") |> to_string() |> String.trim()

  defp task_fingerprint(task) when is_map(task) do
    latest = Map.get(task, "latest_comment", %{}) || %{}

    data =
      [
        Map.get(task, "path", ""),
        to_string(Map.get(task, "line", "")),
        to_string(Map.get(task, "diff_side", "")),
        to_string(Map.get(task, "type", "")),
        to_string(Map.get(task, "comment_total_count", "")),
        to_string(Map.get(task, "comment_count", "")),
        to_string(Map.get(task, "comments_truncated", "")),
        to_string(Map.get(latest, "created_at", "")),
        to_string(Map.get(latest, "author", "")),
        to_string(Map.get(latest, "body", "")),
        to_string(Map.get(task, "body", ""))
      ]
      |> Enum.join("\n")

    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end

  defp map_get_string(nil, _k), do: ""
  defp map_get_string(map, k) when is_map(map), do: Map.get(map, k, "") |> to_string()
  defp map_get_string(_, _), do: ""

  defp map_get_list(nil, _k), do: []
  defp map_get_list(map, k) when is_map(map), do: Map.get(map, k, []) || []
  defp map_get_list(_, _), do: []

  defp map_get_map(nil, _k), do: %{}
  defp map_get_map(map, k) when is_map(map), do: Map.get(map, k, %{}) || %{}
  defp map_get_map(_, _), do: %{}

  defp update_pr_state_after_run(
         state_root,
         pr_number,
         tasks_doc,
         prev_state,
         agent_meta,
         selection,
         diff,
         final_meta,
         _posting_metadata
       )
       when is_integer(pr_number) and is_map(tasks_doc) do
    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    tasks = Map.get(tasks_doc, "tasks", []) || []

    current_thread_ids =
      tasks
      |> Enum.map(&task_thread_id/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    prev_threads = prev_state |> map_get_map("threads")

    threads =
      Enum.reduce(tasks, prev_threads, fn t, acc ->
        tid = task_thread_id(t)

        if tid == "" do
          acc
        else
          fp = task_fingerprint(t)
          loc = task_loc(t)
          excerpt = wrapper_excerpt(Map.get(t, "body", "") |> to_string())

          entry =
            acc
            |> Map.get(tid, %{})
            |> Map.put("open", true)
            |> Map.put("fingerprint", fp)
            |> Map.put("last_seen_at", now)
            |> Map.put("last_task_id", Map.get(t, "id", nil))
            |> Map.put("last_loc", loc)
            |> Map.put("ask_excerpt", excerpt)

          Map.put(acc, tid, entry)
        end
      end)

    # Mark threads resolved if they were open last run but are absent now.
    prev_open = Map.get(diff, :prev_open_ids, []) || []
    current_set = MapSet.new(current_thread_ids)

    threads =
      Enum.reduce(prev_open, threads, fn tid, acc ->
        if MapSet.member?(current_set, tid) do
          acc
        else
          entry =
            acc
            |> Map.get(tid, %{})
            |> Map.put("open", false)
            |> Map.put("resolved_at", now)

          Map.put(acc, tid, entry)
        end
      end)

    threads =
      threads
      |> Enum.reduce(%{}, fn {tid, entry}, acc ->
        # Ensure closed threads that are not in current set remain closed.
        open? = Map.get(entry, "open", false) == true

        entry =
          if open? and not MapSet.member?(current_set, tid) do
            entry |> Map.put("open", false) |> Map.put_new("resolved_at", now)
          else
            entry
          end

        Map.put(acc, tid, entry)
      end)

    threads =
      update_decisions_for_agent_tasks(threads, selection, agent_meta, final_meta, now)

    state =
      %{
        "version" => 1,
        "pr_number" => pr_number,
        "pr_url" => Map.get(tasks_doc, "pr_url", "") |> to_string(),
        "pr_title" => Map.get(tasks_doc, "pr_title", "") |> to_string(),
        "last_run_at" => now,
        "last_open_thread_ids" => current_thread_ids,
        "threads" => threads
      }

    write_pr_state(state_root, pr_number, state)
  end

  defp update_pr_state_after_run(
         _state_root,
         _pr_number,
         _tasks_doc,
         _prev_state,
         _agent_meta,
         _selection,
         _diff,
         _final_meta,
         _posting_metadata
       ),
       do: :ok

  defp update_decisions_for_agent_tasks(threads, selection, agent_meta, _final_meta, now)
       when is_map(threads) do
    agent_tasks = Map.get(selection, :agent_tasks, []) || []

    agent_thread_ids =
      agent_tasks
      |> Enum.map(&task_thread_id/1)
      |> Enum.reject(&(&1 == ""))

    agent_replies_by_tid =
      case agent_meta do
        {:ok, %{"replies" => replies}} when is_list(replies) ->
          replies
          |> Enum.reduce(%{}, fn r, acc ->
            tid = Map.get(r, "thread_id", "") |> to_string() |> String.trim()
            if tid == "", do: acc, else: Map.put(acc, tid, r)
          end)

        _ ->
          :no_meta
      end

    if agent_replies_by_tid == :no_meta do
      threads
    else
      Enum.reduce(agent_thread_ids, threads, fn tid, acc ->
        entry = Map.get(acc, tid, %{})

        {decision, body} =
          case Map.get(agent_replies_by_tid, tid, nil) do
            nil ->
              {"ACCEPT", ""}

            r ->
              d = Map.get(r, "decision", "") |> to_string() |> String.trim()
              b = Map.get(r, "body", "") |> to_string()
              {if(d == "", do: "ANSWER", else: d), b}
          end

        entry =
          entry
          |> Map.put("decision", decision)
          |> Map.put("decision_at", now)
          |> Map.put("reply_body", if(decision in ["ANSWER", "PUSHBACK"], do: body, else: ""))
          |> Map.put("reply_posted_at", nil)

        Map.put(acc, tid, entry)
      end)
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
      "id" => map_get_any(t, :id, "id"),
      "thread_id" => map_get_any(t, :thread_id, "thread_id", ""),
      "path" => map_get_any(t, :path, "path", ""),
      "line" => map_get_any(t, :line, "line"),
      "diff_side" => map_get_any(t, :diff_side, "diff_side"),
      "type" => map_get_any(t, :type, "type", "change"),
      "author" => map_get_any(t, :author, "author", "unknown"),
      "created_at" => map_get_any(t, :created_at, "created_at", ""),
      "comment_count" => map_get_any(t, :comment_count, "comment_count", 0),
      "comment_total_count" => map_get_any(t, :comment_total_count, "comment_total_count"),
      "comments_truncated" => map_get_any(t, :comments_truncated, "comments_truncated"),
      "ask_selected" => map_get_any(t, :ask_selected, "ask_selected", "latest"),
      "ask_note" => map_get_any(t, :ask_note, "ask_note"),
      "thread_opener" => comment_to_json(map_get_any(t, :thread_opener, "thread_opener", %{})),
      "latest_comment" => comment_to_json(map_get_any(t, :latest_comment, "latest_comment", %{})),
      "body" => map_get_any(t, :body, "body", ""),
      "all_comments" => all_comments_to_json(map_get_any(t, :all_comments, "all_comments"))
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

  defp agent_prompt_template(opts, tasks_json_path, root) do
    tasks_abs = Path.expand(tasks_json_path)
    root_abs = Path.expand(root)

    tasks_ref =
      if String.starts_with?(tasks_abs, root_abs <> "/") do
        Path.relative_to(tasks_abs, root_abs)
      else
        tasks_abs
      end

    common_root = Map.get(opts, :common_root, nil)

    {guidelines_path, guidelines_md, include_warnings} =
      AgentReviews.Guidelines.load(root, common_root)

    guidelines_md =
      if is_binary(guidelines_md) and include_warnings != [] do
        warnings_md =
          include_warnings
          |> Enum.uniq()
          |> Enum.map(fn w -> "- " <> w <> "\n" end)
          |> IO.iodata_to_binary()

        "Warnings while expanding `@include`:\n\n" <> warnings_md <> "\n" <> guidelines_md
      else
        guidelines_md
      end

    {always_read_path, always_read} = load_always_read_paths(root, common_root)

    guidance_section =
      build_guidance_section(guidelines_path, guidelines_md, always_read_path, always_read)

    additional_context =
      case Map.get(opts, :additional_comment) do
        comment when is_binary(comment) and comment != "" ->
          """

          ## Additional Context for This Review

          #{comment}
          """

        _ ->
          ""
      end

    """
    # PR Review Implementation Task

    Read `#{tasks_ref}` and implement/respond to each task systematically.
    #{additional_context}
    #{guidance_section}

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

    - You MUST list **all** tasks from `#{tasks_ref}` in order (Task 1..N).
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
    - `thread_id` must come from `#{tasks_ref}` for that task.
    - `decision` must be `ANSWER` or `PUSHBACK`.
    - `top_level_comment` may be an empty string if you don't want a top-level PR comment.
    - The JSON block must be the final fenced ```json block at the end of the file (no other JSON blocks after it).
    """
  end

  defp load_always_read_paths(root, common_root) do
    candidates =
      [root, common_root]
      |> Enum.map(fn
        nil -> nil
        p -> Path.join(p, ".agent_reviews_always_read.txt")
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    Enum.find_value(candidates, {nil, []}, fn path ->
      if File.regular?(path) and File.exists?(path) do
        case File.read(path) do
          {:ok, content} ->
            paths =
              content
              |> String.split(["\r\n", "\n", "\r"], trim: false)
              |> Enum.map(&String.trim/1)
              |> Enum.reject(&(&1 == ""))
              |> Enum.reject(&String.starts_with?(&1, "#"))
              |> Enum.take(25)

            {path, paths}

          _ ->
            nil
        end
      end
    end)
  end

  defp build_guidance_section(nil, nil, nil, []), do: ""

  defp build_guidance_section(guidelines_path, guidelines_md, always_read_path, always_read) do
    always_read_block =
      if is_list(always_read) and always_read != [] do
        label =
          if is_binary(always_read_path) do
            "Always-read list (from `#{always_read_path}`):"
          else
            "Always-read list:"
          end

        [
          label,
          "\n",
          Enum.map(always_read, fn p -> ["- `", p, "`\n"] end),
          "\n"
        ]
      else
        []
      end

    guidelines_block =
      if is_binary(guidelines_md) and String.trim(guidelines_md) != "" do
        label =
          if is_binary(guidelines_path) do
            "Guidelines (from `#{guidelines_path}`):"
          else
            "Guidelines:"
          end

        [
          label,
          "\n\n",
          guidelines_md,
          "\n\n"
        ]
      else
        []
      end

    if always_read_block == [] and guidelines_block == [] do
      ""
    else
      IO.iodata_to_binary([
        "## Repo Guidance (read first)\n",
        "Before deciding/implementing anything, read and follow this repo guidance.\n",
        "If a referenced file doesn't exist, mention it in your output and continue.\n\n",
        always_read_block,
        guidelines_block
      ])
    end
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
    lines = split_lines_trim_end(content)
    has_any_json_fence? = has_any_json_fence?(lines)

    case extract_final_json_fence_parts(lines) do
      {:ok, %{json: json}} ->
        {:ok, json}

      {:error, :empty} ->
        {:error,
         "Could not find a JSON posting metadata code block (```json ... ```) in `#{@agent_dir}/review_responses.md`."}

      {:error, :missing_close} ->
        if has_any_json_fence? do
          {:error,
           "Found a JSON code block, but posting metadata must be the FINAL fenced ```json block at the end of `#{@agent_dir}/review_responses.md`."}
        else
          {:error,
           "Could not find a JSON posting metadata code block (```json ... ```) in `#{@agent_dir}/review_responses.md`."}
        end

      {:error, :missing_open} ->
        {:error,
         "Found a JSON code block, but posting metadata must be the FINAL fenced ```json block at the end of `#{@agent_dir}/review_responses.md`."}
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
    {posted, failed, errors_log, posted_thread_ids} =
      Enum.reduce(replies, {0, 0, nil, []}, fn reply, {posted, failed, errors_log, posted_ids} ->
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
              {posted + 1, failed, errors_log, [thread_id | posted_ids]}

            {:error, out} ->
              errors_log = errors_log || Path.join([root, @agent_dir, "post_errors.log"])
              append_post_error!(errors_log, "task_id=#{task_id} thread_id=#{thread_id}", out)

              IO.puts(
                :stderr,
                "ERROR: Failed to post reply for task_id=#{task_id} (see #{errors_log})."
              )

              {posted, failed + 1, errors_log, posted_ids}
          end
        else
          {:ok, decision} ->
            IO.puts(
              :stderr,
              "WARN: Skipping reply with decision=#{inspect(decision)} (only ANSWER/PUSHBACK are posted)."
            )

            {posted, failed, errors_log, posted_ids}

          {:error, msg} ->
            IO.puts(:stderr, "WARN: Skipping malformed reply entry: #{msg}")
            {posted, failed, errors_log, posted_ids}

          false ->
            IO.puts(:stderr, "WARN: Skipping malformed reply entry.")
            {posted, failed, errors_log, posted_ids}
        end
      end)

    if failed == 0 do
      {:ok, posted, Enum.reverse(posted_thread_ids)}
    else
      errors_log = errors_log || Path.join([root, @agent_dir, "post_errors.log"])

      {:error,
       "Some thread replies failed to post (posted=#{posted}, failed=#{failed}).\nSee: #{errors_log}\n\nCommon causes: missing permissions (fork PR), GitHub auth scope, or rate limits.",
       Enum.reverse(posted_thread_ids)}
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
         tasks_doc,
         tasks_json_path,
         responses_md,
         agent_ran?,
         agent_body,
         changed_files,
         commit_ctx,
         diff,
         prev_state,
         selection,
         carried_replies,
         carried_notes,
         agent_meta,
         final_meta
       ) do
    tasks_rel = Path.relative_to(tasks_json_path, root)
    tasks_list = tasks_list_for_wrapper(tasks_json_path)

    pr_title = Map.get(tasks_doc, "pr_title", "") |> to_string()
    pr_url = Map.get(tasks_doc, "pr_url", "") |> to_string()

    now =
      DateTime.utc_now()
      |> DateTime.to_iso8601()

    changed =
      if changed_files == [] do
        "_No local changes detected._\n"
      else
        changed_files |> Enum.map(fn f -> "- `#{f}`\n" end) |> IO.iodata_to_binary()
      end

    tasks = Map.get(tasks_doc, "tasks", []) || []
    tasks_by_tid = Map.new(tasks, fn t -> {task_thread_id(t), t} end)

    since_last = since_last_section(diff, tasks_by_tid, prev_state, selection, carried_notes)
    carried = carried_replies_section(carried_replies, tasks_by_tid)
    agent_meta_note = agent_meta_note(agent_meta, agent_ran?)

    agent_output =
      cond do
        not agent_ran? and tasks == [] ->
          "_No unresolved review threads found._\n"

        not agent_ran? ->
          "_No new/updated tasks required agent work._\n"

        true ->
          agent_body
          |> to_string()
          |> String.trim_trailing()
          |> Kernel.<>("\n")
      end

    meta_json = Jason.encode!(final_meta, pretty: true) <> "\n"

    doc =
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
        since_last,
        "## Task List\n",
        tasks_list,
        "\n",
        "## Working Tree\n",
        changed,
        "\n",
        carried,
        "---\n",
        "\n",
        "## Agent Output (Last Message)\n",
        "\n",
        agent_meta_note,
        agent_output,
        "\n",
        "## Posting Metadata (final)\n",
        "\n",
        "```json\n",
        meta_json,
        "```\n"
      ]
      |> IO.iodata_to_binary()

    File.write!(responses_md, doc)
    IO.puts("Wrote: #{responses_md}")
    :ok
  end

  defp since_last_section(diff, tasks_by_tid, prev_state, selection, carried_notes)
       when is_map(tasks_by_tid) do
    prev_at = Map.get(diff, :prev_run_at, "") |> to_string() |> String.trim()

    if prev_at == "" do
      ""
    else
      new_items = format_since_last_items(diff.new_ids, tasks_by_tid)
      updated_items = format_since_last_items(diff.updated_ids, tasks_by_tid)
      carried_items = format_since_last_items(diff.carried_ids, tasks_by_tid)
      resolved_items = format_since_last_resolved(diff.resolved_ids, prev_state)

      carried_total = length(diff.carried_ids)

      carried_handled =
        carried_notes
        |> Enum.count(fn {_tid, note} ->
          decision = Map.get(note, "decision", nil) |> to_string() |> String.trim()
          decision in ["ACCEPT", "ANSWER", "PUSHBACK"]
        end)

      agent_tasks = length(Map.get(selection, :agent_tasks, []))

      [
        "## Since Last Run\n",
        "- Previous run: ",
        prev_at,
        "\n",
        "- New: ",
        Integer.to_string(length(diff.new_ids)),
        "\n",
        if(new_items != "", do: [new_items, "\n"], else: []),
        "- Updated: ",
        Integer.to_string(length(diff.updated_ids)),
        "\n",
        if(updated_items != "", do: [updated_items, "\n"], else: []),
        "- Carried forward: ",
        Integer.to_string(carried_total),
        " (previously handled: ",
        Integer.to_string(carried_handled),
        ")\n",
        if(carried_items != "", do: [carried_items, "\n"], else: []),
        "- Resolved since last run: ",
        Integer.to_string(length(diff.resolved_ids)),
        "\n",
        if(resolved_items != "", do: [resolved_items, "\n"], else: []),
        "- Agent tasks this run: ",
        Integer.to_string(agent_tasks),
        "\n\n"
      ]
    end
  end

  defp format_since_last_items(thread_ids, tasks_by_tid) when is_list(thread_ids) do
    thread_ids =
      thread_ids
      |> Enum.uniq()
      |> Enum.sort_by(fn tid ->
        case Map.get(tasks_by_tid, tid) do
          %{"id" => id} when is_integer(id) -> id
          _ -> 9_999_999
        end
      end)

    items =
      thread_ids
      |> Enum.flat_map(fn tid ->
        case Map.get(tasks_by_tid, tid) do
          nil ->
            []

          t ->
            id = Map.get(t, "id", 0)
            loc = task_loc(t)
            suffix = thread_suffix(tid)
            excerpt = wrapper_excerpt(Map.get(t, "body", "") |> to_string())
            ["  - Task ", to_string(id), ": `", loc, "` (thread …", suffix, "): ", excerpt, "\n"]
        end
      end)

    if items == [], do: "", else: IO.iodata_to_binary(items)
  end

  defp format_since_last_resolved(thread_ids, prev_state) when is_list(thread_ids) do
    threads = map_get_map(prev_state, "threads")

    thread_ids =
      thread_ids
      |> Enum.uniq()
      |> Enum.sort_by(fn tid ->
        case Map.get(threads, tid, %{}) do
          %{"last_task_id" => id} when is_integer(id) -> id
          _ -> 9_999_999
        end
      end)

    items =
      thread_ids
      |> Enum.flat_map(fn tid ->
        entry = Map.get(threads, tid, %{})
        loc = Map.get(entry, "last_loc", nil) |> to_string()
        excerpt = Map.get(entry, "ask_excerpt", nil) |> to_string()
        suffix = thread_suffix(tid)

        if String.trim(loc) == "" and String.trim(excerpt) == "" do
          []
        else
          [
            "  - (thread …",
            suffix,
            ") ",
            if(String.trim(loc) != "", do: ["`", loc, "` "], else: []),
            if(String.trim(excerpt) != "", do: [excerpt], else: []),
            "\n"
          ]
        end
      end)

    if items == [], do: "", else: IO.iodata_to_binary(items)
  end

  defp carried_replies_section([], _tasks_by_tid), do: ""

  defp carried_replies_section(replies, tasks_by_tid) when is_list(replies) do
    blocks =
      replies
      |> Enum.flat_map(fn r ->
        tid = Map.get(r, "thread_id", "") |> to_string()
        decision = Map.get(r, "decision", "") |> to_string()
        body = Map.get(r, "body", "") |> to_string() |> String.trim_trailing()
        decision_at = Map.get(r, "decision_at", nil) |> to_string() |> String.trim()

        case Map.get(tasks_by_tid, tid) do
          nil ->
            []

          t ->
            id = Map.get(t, "id", 0)
            loc = task_loc(t)
            suffix = thread_suffix(tid)

            meta =
              [
                "### Task ",
                to_string(id),
                ": carried forward (",
                decision,
                ", thread …",
                suffix,
                ")\n",
                "- Location: `",
                loc,
                "`\n",
                if(decision_at != "", do: ["- Previous response: ", decision_at, "\n"], else: []),
                "\n",
                "**Reply (carried forward):**\n",
                "\n",
                body,
                "\n\n"
              ]

            [meta]
        end
      end)

    if blocks == [] do
      ""
    else
      IO.iodata_to_binary(["## Carried Forward Replies\n\n", blocks, "\n"])
    end
  end

  defp agent_meta_note(_agent_meta, false), do: ""

  defp agent_meta_note(agent_meta, true) do
    case agent_meta do
      {:ok, _} ->
        ""

      {:error, reason} ->
        ["_Note: could not parse agent posting metadata: ", to_string(reason), "_\n\n"]
    end
  end

  defp task_loc(task) when is_map(task) do
    path = Map.get(task, "path", "") |> to_string()
    line = Map.get(task, "line", nil)

    if is_integer(line) do
      "#{path}:#{line}"
    else
      path
    end
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
