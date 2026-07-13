#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# The standard matrix owns the full test suite. Execute the NDK-built Android
# binary against the public fixture tree inside the real Termux app sandbox.
.termux-ci/grafhome-ca check --config-root examples/site-config
