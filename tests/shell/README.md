# Shell tests

- `install-test` builds a schema-faithful synthetic public archive and exercises
  the generated standalone installer. It protects the `bin/grafhome-ca` layout,
  complete non-secret runtime payload, idempotent updates, checksum rollback,
  and preservation of user-owned destinations. The package-smoke CI job
  separately installs the real archive emitted by the release packager.
- `release-scripts-test` owns Grafhome CA's release configuration, payload
  allowlist, and public-archive secret-hygiene contract. Generic release and
  installer machinery remains tested in `cgraf78/actions`.
