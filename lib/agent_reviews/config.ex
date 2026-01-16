defmodule AgentReviews.Config do
  def load_effective_opts(root, opts) do
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
    agent_cmd = System.get_env("AGENT_CMD")
    agent_args = System.get_env("AGENT_ARGS")

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

    opts =
      if is_boolean(checkout_default),
        do: Map.put(opts, :checkout_default, checkout_default),
        else: opts

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
end
