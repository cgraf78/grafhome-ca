# shellcheck shell=bash
#
# grafhome-ca-specific runtime assertions for the shared smoke-release.sh.
#
# The shared script already checks archive naming, the executable bit, that
# every declared payload file shipped, and that every payload directory present
# in the checkout made it into the archive. This adds the checks that require
# actually running the artifact, so it is skipped for cross-built android-*
# archives that cannot execute on the runner.

release_smoke_check() {
  local root=$1

  "$root/bin/grafhome-ca" version
  "$root/bin/grafhome-ca" help >/dev/null
}
