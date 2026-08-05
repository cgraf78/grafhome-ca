# shellcheck shell=bash
#
# grafhome-ca-specific runtime assertions for the shared smoke-release.sh.
#
# The shared script already checks archive naming, the executable bit, that
# every declared payload file shipped, and that every payload directory present
# in the checkout made it into the archive. This adds the checks that require
# actually running the artifact, so it is skipped for cross-built android-*
# archives that cannot execute on the runner.

# Return codes are checked explicitly rather than relying on the caller's
# `set -e`. The shared smoke script treats a non-zero return as failure, and a
# hook whose result depends on ambient shell options can report success after a
# command it ran has already failed.
release_smoke_check() {
  local root=$1

  "$root/bin/grafhome-ca" version || return 1
  "$root/bin/grafhome-ca" help >/dev/null || return 1
}
