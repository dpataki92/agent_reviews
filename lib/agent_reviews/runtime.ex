defmodule AgentReviews.Runtime do
  @moduledoc false

  def invoke_name do
    System.get_env("AGENT_REVIEWS_INVOKE") || "agent_reviews"
  end

  def ensure_cmd(cmd) do
    if System.find_executable(cmd),
      do: :ok,
      else: {:error, "Missing dependency: '#{cmd}' (expected on PATH)"}
  end
end
