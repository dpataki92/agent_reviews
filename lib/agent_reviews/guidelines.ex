defmodule AgentReviews.Guidelines do
  @moduledoc false

  @max_chars 24_000
  @max_depth 5

  def load(root, common_root) do
    home_guidelines = Path.join(System.user_home!(), ".agent_reviews_guidelines.md")

    repo_candidates =
      [common_root, root]
      |> Enum.map(fn
        nil -> nil
        p -> Path.join(p, ".agent_reviews_guidelines.md")
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> Enum.filter(fn path -> File.exists?(path) and File.regular?(path) end)

    user_candidates =
      [home_guidelines]
      |> Enum.filter(fn path -> File.exists?(path) and File.regular?(path) end)

    candidates = user_candidates ++ repo_candidates

    if candidates == [] do
      {nil, nil, []}
    else
      {sections_rev, warnings_rev} =
        Enum.reduce(candidates, {[], []}, fn path, {sections, warns} ->
          {content, warnings} = read_with_includes(path)

          section =
            [
              "### Guidelines from `",
              path,
              "`\n\n",
              content,
              "\n"
            ]
            |> IO.iodata_to_binary()

          {[section | sections], warnings ++ warns}
        end)

      combined =
        sections_rev
        |> Enum.reverse()
        |> Enum.join("\n")
        |> String.trim()

      {nil, combined, Enum.uniq(warnings_rev)}
    end
  end

  def read_with_includes(path) when is_binary(path) do
    path = Path.expand(path)
    allowed_root = Path.dirname(path)

    {content, warnings} =
      do_read_with_includes(path, allowed_root, @max_depth, MapSet.new())

    content = String.trim_trailing(content)

    content =
      if String.length(content) > @max_chars do
        String.slice(content, 0, @max_chars) <> "\n\n_(truncated)_"
      else
        content
      end

    {content, warnings}
  end

  defp do_read_with_includes(_path, _allowed_root, depth, _seen) when depth < 0 do
    {"", ["Include depth limit reached (max_depth=#{@max_depth})."]}
  end

  defp do_read_with_includes(path, allowed_root, depth, seen) do
    path = Path.expand(path)

    cond do
      MapSet.member?(seen, path) ->
        {"", ["Include cycle detected: `#{path}`"]}

      not File.exists?(path) ->
        {"", ["Missing include: `#{path}`"]}

      not File.regular?(path) ->
        {"", ["Include is not a regular file: `#{path}`"]}

      symlink?(path) ->
        {"", ["Include is a symlink (blocked): `#{path}`"]}

      not within_root?(path, allowed_root) ->
        {"", ["Include escapes repo root (blocked): `#{path}`"]}

      true ->
        seen = MapSet.put(seen, path)

        case File.read(path) do
          {:ok, content} ->
            if not String.valid?(content) do
              {"", ["Include is not valid UTF-8: `#{path}`"]}
            else
              base_dir = Path.dirname(path)

              {out, warnings} =
                content
                |> String.split(["\r\n", "\n", "\r"], trim: false)
                |> Enum.reduce({[], []}, fn line, {acc, warns} ->
                  case parse_include_line(line) do
                    nil ->
                      {[line | acc], warns}

                    include_target ->
                      resolved = resolve_include_path(include_target, base_dir)

                      {included, more_warns} =
                        if resolved == nil do
                          {"", ["Invalid include path: `#{include_target}`"]}
                        else
                          do_read_with_includes(resolved, allowed_root, depth - 1, seen)
                        end

                      marker =
                        [
                          "<!-- begin include: ",
                          include_target,
                          " -->\n",
                          included,
                          if(String.trim(included) == "", do: "", else: "\n"),
                          "<!-- end include: ",
                          include_target,
                          " -->"
                        ]
                        |> IO.iodata_to_binary()

                      {[marker | acc], warns ++ more_warns}
                  end
                end)

              {out |> Enum.reverse() |> Enum.join("\n"), warnings}
            end

          {:error, _} ->
            {"", ["Failed to read include: `#{path}`"]}
        end
    end
  end

  defp parse_include_line(line) when is_binary(line) do
    trimmed = String.trim(line)

    case Regex.run(~r/^\s*@include\s+(.+?)\s*$/i, trimmed) do
      [_, rest] ->
        rest
        |> String.trim()
        |> String.trim_leading("`")
        |> String.trim_trailing("`")
        |> String.trim_leading("\"")
        |> String.trim_trailing("\"")
        |> String.trim()
        |> then(fn s -> if(s == "", do: nil, else: s) end)

      _ ->
        nil
    end
  end

  defp resolve_include_path(target, base_dir) when is_binary(target) and is_binary(base_dir) do
    target = String.trim(target)

    cond do
      target == "" ->
        nil

      Path.type(target) == :absolute ->
        nil

      true ->
        Path.expand(Path.join(base_dir, target))
    end
  end

  defp within_root?(path, allowed_root) do
    path = Path.expand(path)
    allowed_root = Path.expand(allowed_root)
    path == allowed_root or String.starts_with?(path, allowed_root <> "/")
  end

  defp symlink?(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :symlink}} -> true
      _ -> false
    end
  end
end
