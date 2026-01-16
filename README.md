# agent-reviews

Local tool to turn unresolved GitHub PR review threads into actionable tasks, run an agent (default: Codex CLI) to implement/respond, and optionally post per-thread replies.

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

- `agent_reviews <pr-number|pr-url|owner/repo#number> [--commit]` (shorthand for `run`)
- `agent_reviews run <pr-number|pr-url|owner/repo#number> [--commit]`
- `agent_reviews post <pr-number|pr-url>`

Target a repo explicitly:

- `agent_reviews -C /path/to/repo run 12345`

Outputs are written under the target repo’s `.agent_review/` directory:

- `tasks.json`
- `review_responses.md` (main user document)
- `state/pr-<n>.json` (internal run history; used to show what’s new/changed since last run and avoid redoing work)

Debug artifacts are only written on failures (e.g. agent logs, raw GitHub API pages).

## Optional repo guidance

If present in the target repo root (committable), these are injected into the agent prompt:

- `.agent_reviews_guidelines.md` (freeform markdown guidance)
- `.agent_reviews_always_read.txt` (one repo-relative path per line; files the agent should read before acting)

`@include` support:

- In `.agent_reviews_guidelines.md`, you can add lines like `@include path/to/file.md` (or quoted) to inline other files (with a small depth/size limit).

## Checkout behavior

- `run` auto-checks out the PR branch via `gh pr checkout`.
- If the working tree is dirty, it refuses to start (clean it up first: commit/stash/reset).

## Parallel PR sessions (worktrees)

If you want to work on multiple PRs concurrently without `.agent_review/` conflicts, use git worktrees:

- `agent_reviews run 123 --worktree`

This creates/uses a per-PR worktree under `<repo_root>/.worktrees/agent_reviews/pr-123` and runs the whole session there.

## Config

Optional config files (simple TOML subset):

- User: `~/.agent_reviews.toml`
- Repo: `<repo_root>/.agent_reviews.toml`

Supported keys:

- `model` (string)
- `reasoning_effort` (string)

Example:

```toml
model = "gpt-5.2"
reasoning_effort = "high"
```

Escape hatch (env vars):

- `AGENT_CMD`
- `AGENT_ARGS`

## Notes

- `run` requires a clean working tree and validates your current HEAD contains the PR head commit recorded in `.agent_review/tasks.json` (branch-name mismatch is a warning).
- Posting expects a final fenced ```json block at the end of `.agent_review/review_responses.md`.

## Local-only ignore for artifacts

This tool writes runtime artifacts under `.agent_review/` in the target repo.

On `run`/`post`, it attempts to add `.agent_review/` and `.worktrees/` to the repo-local exclude file (not committed): `.git/info/exclude`.

If that fails (permissions/worktrees), add it manually:

- `EXCLUDE=$(git rev-parse --git-path info/exclude) && printf '\n# agent_reviews (local-only)\n.agent_review/\n.worktrees/\n' >> "$EXCLUDE"`
