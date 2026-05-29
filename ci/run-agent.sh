#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: ci/run-agent.sh AGENT PROMPT_PATH

Supported AGENT values:
  claude    Run Claude Code non-interactively.
  codex     Run Codex CLI non-interactively.
  opencode  Run OpenCode non-interactively when installed.

The script is intentionally thin. Reachable owns scan, bundle generation,
audit artifacts, and proof. The selected coding agent only consumes prompt.md
and edits the current branch.
EOF
}

if [[ "${1:-}" == "--help" || $# -ne 2 ]]; then
  usage
  exit $([[ "${1:-}" == "--help" ]] && echo 0 || echo 2)
fi

AGENT="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
PROMPT_PATH="$2"

if [[ ! -f "$PROMPT_PATH" ]]; then
  echo "prompt file not found: $PROMPT_PATH" >&2
  exit 2
fi

case "$AGENT" in
  claude)
    command -v claude >/dev/null 2>&1 || {
      echo "claude CLI not found. Install Claude Code or select another agent." >&2
      exit 127
    }
    claude \
      --print \
      --permission-mode bypassPermissions \
      --verbose \
      --output-format stream-json \
      --max-budget-usd "${CLAUDE_MAX_BUDGET_USD:-5}" \
      "$(cat "$PROMPT_PATH")"
    ;;

  codex)
    command -v codex >/dev/null 2>&1 || {
      echo "codex CLI not found. Install Codex or select another agent." >&2
      exit 127
    }
    codex exec \
      -s danger-full-access \
      -C "$PWD" \
      --skip-git-repo-check \
      "$(cat "$PROMPT_PATH")"
    ;;

  opencode)
    command -v opencode >/dev/null 2>&1 || {
      echo "opencode CLI not found. Install OpenCode or select another agent." >&2
      exit 127
    }
    opencode run \
      --dir "$PWD" \
      --dangerously-skip-permissions \
      "$(cat "$PROMPT_PATH")"
    ;;

  *)
    echo "unsupported agent: $AGENT" >&2
    usage
    exit 2
    ;;
esac
