#!/bin/bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Open Vlt Desktop Manager
# @raycast.mode silent
# @raycast.packageName Passwords & Secrets
#
# Optional parameters:
# @raycast.icon 🗄️
# @raycast.description Open full desktop vault manager (3-column GUI, Watchtower, Settings)

"$(cd "$(dirname "$0")" && pwd)/launch-gui.sh" "$@"
