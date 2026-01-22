# agent-reviews

Automate GitHub PR review responses using AI agents (Codex CLI or Claude Code). Fetches unresolved review threads, runs an agent to address them, and optionally posts responses back to GitHub.

## Installation

```bash
# 1. Clone this repo
git clone <repo-url>
cd agent_reviews

# 2. Install dependencies
mix deps.get

# 3. Optional: Build for faster startup
mix escript.build

# 4. Make available globally (choose one)
# Option A: Symlink (recommended)
ln -sf "$(pwd)/bin/agent_reviews" /opt/homebrew/bin/agent_reviews  # macOS (Homebrew)
ln -sf "$(pwd)/bin/agent_reviews" /usr/local/bin/agent_reviews     # Linux or Intel Mac

# Option B: Add to PATH
echo 'export PATH="'$(pwd)'/bin:$PATH"' >> ~/.zshrc  # or ~/.bashrc
```

### Prerequisites

- `elixir` - [Install Elixir](https://elixir-lang.org/install.html)
- `git` - Usually pre-installed
- `gh` - [GitHub CLI](https://cli.github.com/), authenticated with `gh auth login`
- **Agent CLI** (choose one):
  - `codex` - [Codex CLI](https://codex.dev) (default)
  - `claude` - [Claude Code CLI](https://claude.ai/code)

## Usage

### Basic Commands

```bash
# Run in your project repo
cd ~/projects/my-app

# Address PR review feedback (by PR number)
agent_reviews 123

# Explicit run command
agent_reviews run 123

# Auto-commit changes
agent_reviews run 123 --commit

# Add extra instructions for this run only
agent_reviews run 123 -m "Focus on performance, ignore style issues"

# Post responses to GitHub (parses Task Responses from review_responses.md)
agent_reviews post 123

# Clean up for a fresh run (wipes tasks.json, review_responses.md, and state)
agent_reviews clean
```

### PR Reference Formats

```bash
agent_reviews 123                                    # PR number (infers repo from git remote)
agent_reviews https://github.com/owner/repo/pull/123 # Full URL
agent_reviews owner/repo#123                         # owner/repo#number format
agent_reviews -C /path/to/repo run 123               # Run from outside the repo
```

## Choosing Your Agent

### Using Codex (default)

No configuration needed if `codex` is on your PATH:

```bash
agent_reviews 123
```

### Using Claude Code

Set `AGENT_CMD=claude`:

```bash
# One-time
AGENT_CMD=claude agent_reviews 123

# Permanently (add to ~/.zshrc or ~/.bashrc)
export AGENT_CMD=claude

# Then just run
agent_reviews 123
```

**Note:** Claude Code must be authenticated. Run `claude setup-token` or start `claude` interactively and use `/login`.

## Configuration

### Optional Config Files

Create `~/.agent_reviews.toml` (user-level) or `.agent_reviews.toml` (repo-level):

```toml
model = "claude-opus-4"              # Override default model
reasoning_effort = "high"            # Adjust reasoning depth
```

### Environment Variables

```bash
export AGENT_CMD=claude              # Agent to use (codex or claude)
export AGENT_ARGS="--model gpt-4"    # Additional agent arguments
```

## Output Files

After running, check `.agent_review/` in your target repo:

- **`review_responses.md`** - Agent's responses (review this first)
- **`tasks.json`** - Structured task data
- **`state/pr-<n>.json`** - Run history (tracks what's changed since last run)

## Common Options

```bash
--commit                  # Auto-commit changes made by agent
-m, --comment TEXT        # Add extra instructions for this run only
--worktree                # Use git worktree for parallel PR work
--model MODEL             # Override model (e.g., --model gpt-4)
--reasoning-effort LEVEL  # Set reasoning effort (low/medium/high)
-C /path/to/repo          # Target a different repo
```

## Advanced Features

### Custom Guidelines

Guide the agent with custom instructions at two levels:

**User-level** (`~/.agent_reviews_guidelines.md`) - Applied to all repos:
```markdown
# My Preferences
- Always explain your reasoning
- Prefer simple solutions over clever ones
```

**Repo-level** (`.agent_reviews_guidelines.md`) - Project-specific instructions:
```markdown
# Project Guidelines
- Always run tests after changes
- Follow error handling patterns in src/errors.rs
@include docs/style-guide.md
```

Both files support `@include path/to/file.md` to pull in additional content.

**`.agent_reviews_always_read.txt`** - Files the agent should read first:
```
CONTRIBUTING.md
ARCHITECTURE.md
docs/api-guide.md
```

### Parallel PR Work

Use worktrees to work on multiple PRs simultaneously:

```bash
# Terminal 1
agent_reviews 123 --worktree  # Creates .worktrees/agent_reviews/pr-123/

# Terminal 2
agent_reviews 456 --worktree  # Creates .worktrees/agent_reviews/pr-456/
```

Each PR gets isolated state—no conflicts!

## How It Works

1. **Checkout** - Checks out the PR branch via `gh pr checkout`
2. **Fetch** - Retrieves unresolved review threads from GitHub
3. **Diff** - Compares with previous run to identify new/changed threads
4. **Invoke** - Runs agent with structured task list + repo context
5. **Capture** - Saves agent's responses to `review_responses.md`
6. **Review** - You review and edit the Task Responses section as needed
7. **Commit** - Optionally commits file changes (with `--commit`)
8. **Post** - Parses Task Responses from MD and posts to GitHub (with `post` command)

**State tracking:** Only processes new/changed threads on subsequent runs, avoiding duplicate work.

**Fresh start:** Use `agent_reviews clean` to wipe all state and start over (useful when switching agents or re-running from scratch).

## License

MIT
