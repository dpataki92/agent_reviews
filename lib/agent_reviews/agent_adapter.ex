defmodule AgentReviews.AgentAdapter do
  @moduledoc """
  Adapter interface for different agent CLIs (Codex, Claude).

  This module hides agent-specific command-line differences so the rest of the
  tool can stay agent-agnostic.
  """

  @type agent_type :: :codex | :claude

  @spec detect_agent_type(binary()) :: {:ok, agent_type()} | {:error, :unknown}
  def detect_agent_type(agent_cmd) when is_binary(agent_cmd) do
    base = agent_cmd |> Path.basename() |> String.downcase()

    cond do
      String.contains?(base, "claude") -> {:ok, :claude}
      String.contains?(base, "codex") -> {:ok, :codex}
      true -> detect_from_help(agent_cmd)
    end
  end

  @spec build_exec_args(agent_type(), binary(), binary() | nil, [binary()], map()) ::
          {:ok, [binary()]} | {:error, binary()}
  def build_exec_args(agent_type, root, output_file, agent_args, opts)
      when agent_type in [:codex, :claude] and is_list(agent_args) and is_map(opts) do
    root = Path.expand(root)

    args =
      agent_type
      |> build_model_args(opts)
      |> Kernel.++(agent_args)
      |> maybe_add_auto_approval(agent_type)

    case agent_type do
      :codex ->
        if not is_binary(output_file) or String.trim(output_file) == "" do
          {:error, "Internal error: missing output file for Codex last-message capture."}
        else
          {:ok, ["exec", "-C", root, "--output-last-message", output_file] ++ args ++ ["-"]}
        end

      :claude ->
        # Claude Code supports non-interactive output via -p/--print. It can read the prompt from stdin.
        #
        # Use `--output-format json` to make output capture deterministic and easy to parse.
        {:ok, ["-p", "--output-format", "json", "--no-session-persistence"] ++ args}
    end
  end

  @spec claude_result_from_output(binary()) ::
          {:ok, %{result: binary(), is_error?: boolean()}} | :error
  def claude_result_from_output(output) when is_binary(output) do
    output = String.trim(output)

    case Jason.decode(output) do
      {:ok, decoded} when is_map(decoded) ->
        decode_claude_result_map(decoded)

      _ ->
        # Claude normally emits a single-line JSON object on stdout. If stderr is merged in, try to
        # decode the last JSON-looking line.
        line =
          output
          |> String.split(["\r\n", "\n", "\r"], trim: true)
          |> Enum.reverse()
          |> Enum.find(fn l ->
            l = String.trim(l)
            String.starts_with?(l, "{") and String.ends_with?(l, "}")
          end)

        if is_binary(line) do
          case Jason.decode(String.trim(line)) do
            {:ok, decoded} when is_map(decoded) -> decode_claude_result_map(decoded)
            _ -> :error
          end
        else
          :error
        end
    end
  rescue
    _ -> :error
  end

  defp decode_claude_result_map(decoded) do
    case Map.get(decoded, "result") do
      result when is_binary(result) ->
        is_error? =
          case Map.get(decoded, "is_error") do
            true -> true
            _ -> false
          end

        {:ok, %{result: result, is_error?: is_error?}}

      _ ->
        :error
    end
  end

  @spec validate_noninteractive_support(binary(), agent_type()) :: :ok | {:error, binary()}
  def validate_noninteractive_support(agent_cmd, :codex) when is_binary(agent_cmd) do
    {out, status} = System.cmd(agent_cmd, ["exec", "--help"], stderr_to_stdout: true)

    if status == 0 do
      :ok
    else
      {:error,
       "Your agent must support non-interactive execution.\n\nTried: #{agent_cmd} exec --help\n\nOutput:\n#{out}\n\nHint: upgrade Codex CLI, or set AGENT_CMD to the correct executable."}
    end
  end

  def validate_noninteractive_support(agent_cmd, :claude) when is_binary(agent_cmd) do
    {out, status} = System.cmd(agent_cmd, ["--help"], stderr_to_stdout: true)

    cond do
      status != 0 ->
        {:error,
         "Your agent must support non-interactive execution.\n\nTried: #{agent_cmd} --help\n\nOutput:\n#{out}\n\nHint: upgrade Claude Code CLI, or set AGENT_CMD to the correct executable."}

      not String.contains?(out, "--print") and not String.contains?(out, "-p") ->
        {:error,
         "Claude Code CLI must support non-interactive `-p/--print` mode.\n\nTried: #{agent_cmd} --help\n\nOutput:\n#{out}"}

      true ->
        :ok
    end
  end

  @spec build_model_args(agent_type(), map()) :: [binary()]
  def build_model_args(:codex, opts) when is_map(opts) do
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

  def build_model_args(:claude, opts) when is_map(opts) do
    model_args =
      case Map.get(opts, :model) do
        m when is_binary(m) and m != "" -> ["--model", m]
        _ -> []
      end

    reasoning_note =
      case Map.get(opts, :reasoning_effort) do
        r when is_binary(r) and r != "" ->
          [
            "--append-system-prompt",
            "Reasoning effort: #{r}. Adjust your depth/verbosity accordingly."
          ]

        _ ->
          []
      end

    model_args ++ reasoning_note
  end

  @spec maybe_add_auto_approval([binary()], agent_type()) :: [binary()]
  def maybe_add_auto_approval(args, :codex) when is_list(args) do
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

  def maybe_add_auto_approval(args, :claude) when is_list(args) do
    has_permission_mode? =
      Enum.any?(args, fn
        "--permission-mode" -> true
        "--dangerously-skip-permissions" -> true
        "--allow-dangerously-skip-permissions" -> true
        _ -> false
      end)

    if has_permission_mode?, do: args, else: ["--permission-mode", "bypassPermissions" | args]
  end

  @spec failure_hint(agent_type(), binary()) :: binary()
  def failure_hint(:codex, output) when is_binary(output) do
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

  def failure_hint(:claude, output) when is_binary(output) do
    cond do
      String.contains?(output, "Invalid API key") or String.contains?(output, "/login") ->
        "\nHint: Claude Code is not authenticated. Run `claude setup-token` or start `claude` interactively and run `/login`, then retry."

      String.contains?(output, "EPERM") and String.contains?(output, ".claude") ->
        "\nHint: Claude Code is failing to write config/session files under your HOME. Fix permissions for HOME (or run from a writable HOME)."

      true ->
        ""
    end
  end

  def failure_hint(_, _), do: ""

  defp detect_from_help(agent_cmd) do
    {out, status} = System.cmd(agent_cmd, ["--help"], stderr_to_stdout: true)

    if status == 0 do
      cond do
        String.contains?(out, "Claude Code") -> {:ok, :claude}
        String.contains?(out, "Codex CLI") -> {:ok, :codex}
        true -> {:error, :unknown}
      end
    else
      {:error, :unknown}
    end
  rescue
    _ -> {:error, :unknown}
  end

  defp toml_string(value) do
    escaped =
      value
      |> to_string()
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")

    ~s("#{escaped}")
  end
end
