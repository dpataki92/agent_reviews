defmodule AgentReviews.GuidelinesTest do
  use ExUnit.Case, async: true

  test "@include expands files within repo root" do
    root = tmp_dir("guidelines-include-ok")
    File.mkdir_p!(root)

    include_path = Path.join(root, "included.md")
    File.write!(include_path, "Included content")

    guidelines_path = Path.join(root, ".agent_reviews_guidelines.md")
    File.write!(guidelines_path, "@include included.md\n")

    {content, warnings} = AgentReviews.Guidelines.read_with_includes(guidelines_path)

    assert warnings == []
    assert content =~ "Included content"
  end

  test "@include blocks path traversal outside repo root" do
    base = tmp_dir("guidelines-include-traversal")
    repo = Path.join(base, "repo")
    outside_dir = Path.join(base, "outside")
    File.mkdir_p!(repo)
    File.mkdir_p!(outside_dir)

    outside_path = Path.join(outside_dir, "secret.md")
    File.write!(outside_path, "SECRET")

    guidelines_path = Path.join(repo, ".agent_reviews_guidelines.md")
    File.write!(guidelines_path, "@include ../outside/secret.md\n")

    {content, warnings} = AgentReviews.Guidelines.read_with_includes(guidelines_path)

    assert Enum.any?(warnings, &String.contains?(&1, "escapes repo root"))
    refute content =~ "SECRET"
  end

  test "@include blocks absolute paths" do
    root = tmp_dir("guidelines-include-abs")
    File.mkdir_p!(root)

    guidelines_path = Path.join(root, ".agent_reviews_guidelines.md")
    File.write!(guidelines_path, "@include /etc/passwd\n")

    {_content, warnings} = AgentReviews.Guidelines.read_with_includes(guidelines_path)

    assert Enum.any?(warnings, &String.contains?(&1, "Invalid include path"))
  end

  test "@include detects cycles" do
    root = tmp_dir("guidelines-include-cycle")
    File.mkdir_p!(root)

    a = Path.join(root, "a.md")
    b = Path.join(root, "b.md")
    File.write!(a, "@include b.md\nA\n")
    File.write!(b, "@include a.md\nB\n")

    {content, warnings} = AgentReviews.Guidelines.read_with_includes(a)

    assert content =~ "A"
    assert content =~ "B"
    assert Enum.any?(warnings, &String.contains?(&1, "cycle detected"))
  end

  test "@include blocks symlinks when supported" do
    base = tmp_dir("guidelines-include-symlink")
    repo = Path.join(base, "repo")
    outside_dir = Path.join(base, "outside")
    File.mkdir_p!(repo)
    File.mkdir_p!(outside_dir)

    outside_path = Path.join(outside_dir, "secret.md")
    File.write!(outside_path, "SECRET")

    link_path = Path.join(repo, "link.md")

    case File.ln_s(outside_path, link_path) do
      :ok ->
        guidelines_path = Path.join(repo, ".agent_reviews_guidelines.md")
        File.write!(guidelines_path, "@include link.md\n")

        {content, warnings} = AgentReviews.Guidelines.read_with_includes(guidelines_path)

        assert Enum.any?(warnings, &String.contains?(&1, "symlink"))
        refute content =~ "SECRET"

      {:error, _} ->
        :ok
    end
  end

  defp tmp_dir(prefix) do
    Path.join(System.tmp_dir!(), "#{prefix}-#{System.unique_integer([:positive])}")
  end
end
