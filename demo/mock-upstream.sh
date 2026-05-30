#!/usr/bin/env bash
# Minimal mock MCP upstream: reads JSON-RPC requests on stdin and
# emits canned responses on stdout. Used only by demo/demo.tape.
while IFS= read -r line; do
  id=$(echo "$line" | jq -r '.id // empty')
  if [ -n "$id" ]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\n' "$id"
  fi
done
