#!/bin/bash
# Locate the real moon compiler binary
REAL_MOON=""
if [[ -f "$HOME/.moon/bin/moon.exe" ]]; then
  REAL_MOON="$HOME/.moon/bin/moon.exe"
elif [[ -f "$HOME/.moon/bin/moon" ]]; then
  REAL_MOON="$HOME/.moon/bin/moon"
elif [[ -f "C:/Users/runneradmin/.moon/bin/moon.exe" ]]; then
  REAL_MOON="C:/Users/runneradmin/.moon/bin/moon.exe"
else
  REAL_MOON=$(which -a moon | grep -v "bin/moon" | head -n 1)
fi

CMD=""
ARGS=()
HAS_DENY_WARN=false

for arg in "$@"; do
  if [[ "$arg" == "fmt" ]]; then
    CMD="fmt"
    ARGS+=("fmt")
  elif [[ "$arg" == "info" ]]; then
    CMD="info"
    ARGS+=("info")
  elif [[ "$arg" == "--deny-warn" ]]; then
    HAS_DENY_WARN=true
  else
    ARGS+=("$arg")
  fi
done

if [[ "$CMD" == "fmt" ]]; then
  # Strip --deny-warn and add --check
  HAS_CHECK=false
  for a in "${ARGS[@]}"; do
    if [[ "$a" == "--check" ]]; then
      HAS_CHECK=true
    fi
  done
  if [[ "$HAS_CHECK" == false ]]; then
    ARGS+=("--check")
  fi
elif [[ "$CMD" == "info" ]]; then
  # Strip --deny-warn
  :
else
  if [[ "$HAS_DENY_WARN" == true ]]; then
    ARGS+=("--deny-warn")
  fi
fi

exec "$REAL_MOON" "${ARGS[@]}"
