defmodule AgentReviews.AgentAdapterTest do
  use ExUnit.Case, async: true

  alias AgentReviews.AgentAdapter

  test "detect_agent_type prefers basename heuristics" do
    assert {:ok, :claude} = AgentAdapter.detect_agent_type("/usr/local/bin/claude")
    assert {:ok, :codex} = AgentAdapter.detect_agent_type("/opt/homebrew/bin/codex")
  end

  test "build_exec_args for codex includes exec wrapper and stdin marker" do
    root = "/tmp/repo"
    out = "/tmp/last.md"

    {:ok, args} =
      AgentAdapter.build_exec_args(:codex, root, out, ["--model", "gpt-5"], %{
        model: nil,
        reasoning_effort: nil
      })

    assert Enum.take(args, 5) == ["exec", "-C", Path.expand(root), "--output-last-message", out]
    assert List.last(args) == "-"
  end

  test "build_exec_args for claude includes print mode and no-session-persistence" do
    root = "/tmp/repo"

    {:ok, args} =
      AgentAdapter.build_exec_args(:claude, root, nil, ["--model", "sonnet"], %{
        model: nil,
        reasoning_effort: nil
      })

    assert Enum.take(args, 4) == ["-p", "--output-format", "json", "--no-session-persistence"]
  end

  test "maybe_add_auto_approval defaults" do
    assert AgentAdapter.maybe_add_auto_approval(["--model", "x"], :codex) |> hd() == "--full-auto"

    assert AgentAdapter.maybe_add_auto_approval(["--model", "x"], :claude) |> hd() ==
             "--permission-mode"

    assert AgentAdapter.maybe_add_auto_approval(["--full-auto"], :codex) == ["--full-auto"]

    assert AgentAdapter.maybe_add_auto_approval(["--permission-mode", "default"], :claude) ==
             ["--permission-mode", "default"]
  end

  test "validate_noninteractive_support can be exercised with stub executables" do
    dir =
      Path.join(System.tmp_dir!(), "agent-reviews-adapter-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)

    codex = Path.join(dir, "codex")

    File.write!(
      codex,
      """
      #!/bin/sh
      if [ "$1" = "exec" ] && [ "$2" = "--help" ]; then
        echo "codex exec help"
        exit 0
      fi
      exit 1
      """
    )

    File.chmod!(codex, 0o755)
    assert :ok == AgentAdapter.validate_noninteractive_support(codex, :codex)

    claude = Path.join(dir, "claude")

    File.write!(
      claude,
      """
      #!/bin/sh
      if [ "$1" = "--help" ]; then
        echo "Claude Code"
        echo "-p, --print"
        exit 0
      fi
      exit 1
      """
    )

    File.chmod!(claude, 0o755)
    assert :ok == AgentAdapter.validate_noninteractive_support(claude, :claude)
  end
end
