#!/bin/bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Vlt Quick Search
# @raycast.mode silent
# @raycast.packageName Passwords & Secrets
#
# Optional parameters:
# @raycast.icon 🔑
# @raycast.description Search and copy passwords with vlt Quick Access

"$(cd "$(dirname "$0")" && pwd)/launch-quick.sh" "$@"
