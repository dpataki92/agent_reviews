defmodule AgentReviews.ExtractRepliesTest do
  use ExUnit.Case, async: true

  alias AgentReviews.CLI

  # Task map: task_id -> thread_id
  @task_map %{
    1 => "PRRT_thread_1",
    2 => "PRRT_thread_2",
    3 => "PRRT_thread_3"
  }

  describe "extract_replies_from_md/2" do
    test "extracts single reply with ANSWER decision" do
      content = """
      ## Agent Output (Last Message)

      ### Task Responses

      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Please fix the bug"
      **Decision:** ANSWER

      **Reply:**
      Yes, I fixed the bug by updating the condition.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["task_id"] == 1
      assert reply["thread_id"] == "PRRT_thread_1"
      assert reply["decision"] == "ANSWER"
      assert reply["body"] == "Yes, I fixed the bug by updating the condition."
    end

    test "extracts single reply with PUSHBACK decision" do
      content = """
      #### Task 2: `lib/bar.ex:10` (`question`)
      **Ask (excerpt):** "Why did you do this?"
      **Decision:** PUSHBACK

      **Reply:**
      I disagree with this approach because it would break backwards compatibility.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["task_id"] == 2
      assert reply["decision"] == "PUSHBACK"

      assert reply["body"] ==
               "I disagree with this approach because it would break backwards compatibility."
    end

    test "extracts multiple replies" do
      content = """
      ### Task Responses

      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Fix bug A"
      **Decision:** ANSWER

      **Reply:**
      Fixed bug A.

      ---

      #### Task 2: `lib/bar.ex:10` (`change`)
      **Ask (excerpt):** "Fix bug B"
      **Decision:** ANSWER

      **Reply:**
      Fixed bug B.

      ---
      """

      assert {:ok, replies} = CLI.extract_replies_from_md(content, @task_map)
      assert length(replies) == 2
      assert Enum.at(replies, 0)["task_id"] == 1
      assert Enum.at(replies, 1)["task_id"] == 2
    end

    test "handles multiline reply body" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Explain this"
      **Decision:** ANSWER

      **Reply:**
      This is a multiline reply.

      It has multiple paragraphs.

      And even more content here.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["body"] =~ "multiline reply"
      assert reply["body"] =~ "multiple paragraphs"
      assert reply["body"] =~ "even more content"
    end

    test "handles reply body with code blocks" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Show code example"
      **Decision:** ANSWER

      **Reply:**
      Here's the fix:

      ```elixir
      def hello do
        :world
      end
      ```

      This should work now.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["body"] =~ "```elixir"
      assert reply["body"] =~ "def hello do"
      assert reply["body"] =~ "```"
    end

    test "handles reply body with markdown formatting" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Format test"
      **Decision:** ANSWER

      **Reply:**
      Here's a list:
      - Item 1
      - Item 2
      - **Bold item**

      And a `code snippet` inline.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["body"] =~ "- Item 1"
      assert reply["body"] =~ "**Bold item**"
      assert reply["body"] =~ "`code snippet`"
    end

    test "returns error when tasks found but none match task_map" do
      content = """
      #### Task 999: `lib/unknown.ex:1` (`change`)
      **Ask (excerpt):** "Unknown task"
      **Decision:** ANSWER

      **Reply:**
      This should be skipped.

      ---
      """

      assert {:error, msg} = CLI.extract_replies_from_md(content, @task_map)
      assert msg =~ "Found 1 task responses but could not match any"
    end

    test "returns empty list when no task responses found" do
      content = """
      ## Agent Output (Last Message)

      No tasks to respond to.
      """

      assert {:ok, []} = CLI.extract_replies_from_md(content, @task_map)
    end

    test "handles decision with extra whitespace" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Test"
      **Decision:**   ANSWER

      **Reply:**
      Reply text.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["decision"] == "ANSWER"
    end

    test "handles lowercase decision" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Test"
      **Decision:** answer

      **Reply:**
      Reply text.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["decision"] == "ANSWER"
    end

    test "stops at next ## section" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Test"
      **Decision:** ANSWER

      **Reply:**
      Reply text that should be captured.

      ## Next Section

      This should not be captured.
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["body"] == "Reply text that should be captured."
      refute reply["body"] =~ "Next Section"
    end

    test "handles task without trailing ---" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "Test"
      **Decision:** ANSWER

      **Reply:**
      Reply at end of file without separator.
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["body"] == "Reply at end of file without separator."
    end

    test "extracts only tasks with Reply section" do
      content = """
      #### Task 1: `lib/foo.ex:42` (`change`)
      **Ask (excerpt):** "This is ACCEPT, no reply"
      **Decision:** ACCEPT
      - Made the change as requested

      ---

      #### Task 2: `lib/bar.ex:10` (`question`)
      **Ask (excerpt):** "Need a reply"
      **Decision:** ANSWER

      **Reply:**
      Here is my answer.

      ---
      """

      assert {:ok, replies} = CLI.extract_replies_from_md(content, @task_map)
      # Only task 2 has a Reply section
      assert length(replies) == 1
      assert Enum.at(replies, 0)["task_id"] == 2
    end

    test "handles real-world complex reply with nested code" do
      content = """
      #### Task 1: `backend/lib/backend/users.ex:984` (`change`)
      **Ask (excerpt):** "I might be misunderstanding how this works but doesn't the cleanup job..."
      **Decision:** ANSWER

      **Reply:**
      Yes, the concern is valid. After investigating the code flow:

      1. **In `delete_records/3`** (lines 941-986): The transaction deletes all user data.

      2. **After transaction success** (line 984): `enqueue_stream_cleanup(user_id, organisation_id)` is called.

      **Potential solutions**:

      1. **Capture feed/channel IDs before deletion**:
         ```elixir
         # Before transaction
         feed_ids = Feeds.get_user_subscribed_feeds(user_id) |> Enum.map(& &1.id)
         channel_ids = Engagement.get_chat_channels_for_user(user_id, org_id) |> Enum.map(& &1.id)

         # Pass to worker
         enqueue_stream_cleanup(user_id, org_id, feed_ids, channel_ids)
         ```

      2. **Query Stream directly** instead of our database.

      ---
      """

      assert {:ok, [reply]} = CLI.extract_replies_from_md(content, @task_map)
      assert reply["task_id"] == 1
      assert reply["decision"] == "ANSWER"
      assert reply["body"] =~ "Yes, the concern is valid"
      assert reply["body"] =~ "```elixir"
      assert reply["body"] =~ "feed_ids = Feeds.get_user_subscribed_feeds"
      assert reply["body"] =~ "Query Stream directly"
    end
  end
end
