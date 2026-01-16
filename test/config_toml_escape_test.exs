defmodule AgentReviews.ConfigTomlEscapeTest do
  use ExUnit.Case, async: false

  setup do
    old_home = System.get_env("HOME")

    home =
      Path.join(System.tmp_dir!(), "agent-reviews-home-#{System.unique_integer([:positive])}")

    File.mkdir_p!(home)
    System.put_env("HOME", home)

    on_exit(fn ->
      if is_binary(old_home),
        do: System.put_env("HOME", old_home),
        else: System.delete_env("HOME")
    end)

    %{home: home}
  end

  test "parses common TOML escapes (\\n, \\t, \\uXXXX)", %{home: home} do
    cfg = Path.join(home, ".agent_reviews.toml")

    File.write!(
      cfg,
      ~s(model = "hello\\nworld"\nreasoning_effort = "hi\\tthere\\u263A"\n)
    )

    root =
      Path.join(System.tmp_dir!(), "agent-reviews-root-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)

    {:ok, opts} =
      AgentReviews.Config.load_effective_opts(root, %{model: nil, reasoning_effort: nil})

    assert opts.model == "hello\nworld"
    assert opts.reasoning_effort == "hi\tthere☺"
  end
end
