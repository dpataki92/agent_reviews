defmodule AgentReviews.Config do
  @moduledoc false

  def load_effective_opts(root, opts) do
    defaults = %{
      model: nil,
      reasoning_effort: nil
    }

    user_cfg_path = Path.join(user_home!(), ".agent_reviews.toml")
    repo_cfg_path = Path.join(root, ".agent_reviews.toml")

    with {:ok, user_cfg} <- read_optional_config(user_cfg_path),
         {:ok, repo_cfg} <- read_optional_config(repo_cfg_path) do
      cfg =
        defaults
        |> Map.merge(user_cfg)
        |> Map.merge(repo_cfg)

      {:ok, apply_config_to_opts(opts, apply_env_overrides(cfg))}
    end
  end

  defp user_home! do
    home = System.get_env("HOME")

    if is_binary(home) and String.trim(home) != "" do
      home
    else
      System.user_home!()
    end
  end

  defp apply_env_overrides(cfg) do
    agent_cmd = System.get_env("AGENT_CMD")
    agent_args = System.get_env("AGENT_ARGS")

    cfg
    |> Map.put_new(:agent_cmd, "codex")
    |> Map.put_new(:agent_args, "")
    |> maybe_put_string(:agent_cmd, agent_cmd)
    |> maybe_put_string(:agent_args, agent_args)
  end

  defp maybe_put_string(map, _k, nil), do: map

  defp maybe_put_string(map, k, v) do
    v = String.trim(to_string(v))
    if v == "", do: map, else: Map.put(map, k, v)
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
    lines =
      content
      |> String.split("\n", trim: false)

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
        "model" -> {:ok, {:model, to_string(value)}}
        "reasoning_effort" -> {:ok, {:reasoning_effort, to_string(value)}}
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
    s = to_string(s)
    do_toml_unescape(s, "")
  end

  defp do_toml_unescape(<<>>, acc), do: acc

  defp do_toml_unescape(<<"\\", rest::binary>>, acc) do
    case rest do
      <<"n", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\n")

      <<"t", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\t")

      <<"r", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\r")

      <<"b", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\b")

      <<"f", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\f")

      <<"\\", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\\")

      <<"\"", tail::binary>> ->
        do_toml_unescape(tail, acc <> "\"")

      <<"u", a::binary-size(4), tail::binary>> ->
        case Integer.parse(a, 16) do
          {codepoint, ""} when codepoint <= 0x10FFFF ->
            do_toml_unescape(tail, acc <> <<codepoint::utf8>>)

          _ ->
            do_toml_unescape(tail, acc <> "\\u" <> a)
        end

      <<char::utf8, tail::binary>> ->
        do_toml_unescape(tail, acc <> "\\" <> <<char::utf8>>)

      _ ->
        acc <> "\\"
    end
  end

  defp do_toml_unescape(<<char::utf8, rest::binary>>, acc),
    do: do_toml_unescape(rest, acc <> <<char::utf8>>)

  defp apply_config_to_opts(opts, cfg) do
    opts = Map.put(opts, :agent_cmd, Map.get(cfg, :agent_cmd, "codex"))
    opts = Map.put(opts, :agent_args, Map.get(cfg, :agent_args, ""))

    opts =
      if is_nil(Map.get(opts, :model)),
        do: Map.put(opts, :model, Map.get(cfg, :model, nil)),
        else: opts

    opts =
      if is_nil(Map.get(opts, :reasoning_effort)),
        do: Map.put(opts, :reasoning_effort, Map.get(cfg, :reasoning_effort, nil)),
        else: opts

    opts
  end
end
