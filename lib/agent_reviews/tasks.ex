defmodule AgentReviews.Tasks do
  @moduledoc false

  def tasks_yaml(pr_title, pr_url, head_ref, base_ref, head_sha, base_sha, tasks) do
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
            if(is_integer(Map.get(t, :comment_total_count, nil)),
              do: Integer.to_string(t.comment_total_count),
              else: "null"
            ),
            "\n",
            "    comments_truncated: ",
            if(is_boolean(Map.get(t, :comments_truncated, nil)),
              do: yaml_bool(t.comments_truncated),
              else: "null"
            ),
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

  def tasks_md(pr_title, pr_url, tasks) do
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
                    {"comments: #{Map.get(t, :comment_count, 1)}",
                     Map.get(t, :comment_count, 1) > 1}
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

              [
                "- [ ] Task ",
                Integer.to_string(t.id),
                " (",
                meta,
                "): ",
                summary,
                multi_note,
                "\n"
              ]
            end),
            "\n"
          ]
        end)

      IO.iodata_to_binary([header, sections])
    end
  end

  def thread_suffix(thread_id) when is_binary(thread_id) do
    tid = String.trim(thread_id)

    cond do
      tid == "" -> "????"
      String.length(tid) <= 8 -> tid
      true -> String.slice(tid, -8, 8)
    end
  end

  def thread_suffix(_), do: "????"

  def summarize(body) do
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
end
