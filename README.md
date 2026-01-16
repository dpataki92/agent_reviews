# agent-reviews

Local tool to turn unresolved GitHub PR review threads into actionable tasks for Codex CLI, apply them, and optionally post per-thread replies.

## Install

Option A (symlink):

- `ln -sf /path/to/agent-reviews/bin/agent_reviews /opt/homebrew/bin/agent_reviews`  # Apple Silicon
- `ln -sf /path/to/agent-reviews/bin/agent_reviews /usr/local/bin/agent_reviews`    # Intel

Option B (PATH):

- Add `/path/to/agent-reviews/bin` to your PATH.

First run (once, in this repo):

- `mix deps.get`
- Optional (faster startup): `mix escript.build` (creates `./agent_reviews`)

## Prerequisites

- `elixir` (includes `mix`)
- `git`
- `gh` (authenticated via `gh auth login`)
- `codex` (Codex CLI; set `AGENT_CMD` if it’s not on PATH)

## Usage

Run inside a target repo, or point at one:

- `agent_reviews fetch <pr-number|pr-url|owner/repo#number>`
- `agent_reviews apply [--commit]`
- `agent_reviews run <pr-number|pr-url|owner/repo#number> [--commit]`
- `agent_reviews post <pr-number|pr-url> [--fallback-top-level]`
- `agent_reviews config`

Target a repo explicitly:

- `agent_reviews -C /path/to/repo run 12345`

Outputs are written under the target repo’s `.agent/` directory.

## Checkout behavior

- `run` auto-checks out the PR branch by default via `gh pr checkout`.
- Use `--no-checkout` to disable, or `--checkout` to enable it for `fetch`/`post`.
- If the working tree is dirty and checkout is enabled, the tool will prompt to stash (TTY) or you can pass `--stash`.

## Parallel PR sessions (worktrees)

If you want to work on multiple PRs concurrently without `.agent/` conflicts, use git worktrees:

- `agent_reviews run 123 --worktree`

This creates/uses a per-PR worktree under `<repo_root>/.worktrees/agent_reviews/pr-123` and runs the whole session there.

## Config

Optional config files (simple TOML subset):

- User: `~/.agent_reviews.toml`
- Repo: `<repo_root>/.agent_reviews.toml`
- Extra: `--config /path/to/file.toml` (repeatable; later files win)

Supported keys:

- `agent_cmd` (string, default: "codex")
- `agent_args` (string, shellwords)
- `model` (string)
- `reasoning_effort` (string)
- `full_auto` (bool, default: true)
- `skip_nitpicks` (bool, default: false)
- `auto_commit` (bool, default: false)
- `verbose` (bool, default: false)
- `checkout_default` (bool, optional)

Example:

```toml
model = "gpt-5.2"
reasoning_effort = "high"
skip_nitpicks = true
checkout_default = true
```

You can also use env vars:

- `AGENT_CMD`
- `AGENT_ARGS`

Run `agent_reviews config` to see effective settings.

## Notes

- `apply` requires a clean working tree and validates your current HEAD contains the PR head commit recorded in `.agent/tasks.json` (branch-name mismatch is a warning).
- Posting expects a final fenced ```json block at the end of `.agent/review_responses.md`.

## Local-only ignore for artifacts

This tool writes runtime artifacts under `.agent/` in the target repo.

On `fetch`/`apply`/`run`/`post`, it attempts to add `.agent/` and `.worktrees/` to the repo-local exclude file (not committed): `.git/info/exclude`.

If that fails (permissions/worktrees), add it manually:

- `EXCLUDE=$(git rev-parse --git-path info/exclude) && printf '\n# agent_reviews (local-only)\n.agent/\n.worktrees/\n' >> "$EXCLUDE"`
