defmodule AgentReviews.MixProject do
  use Mix.Project

  def project do
    [
      app: :agent_reviews,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      escript: escript(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp escript do
    [main_module: AgentReviews.CLI]
  end

  defp deps do
    [
      {:jason, "~> 1.4"}
    ]
  end
end
