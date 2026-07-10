# Grafhome CA

Grafhome CA is the policy, validation, packaging, and lifecycle tooling for the
Grafhome SSH certificate authority. The CA cryptographic boundary stays in
Smallstep: `step-ca` runs the server and `step` performs client operations.
This repo owns the typed local policy model, schemas, templates, packaging, and
operator commands. Real site policy is loaded at runtime from the XDG config
root and should live in a private repo or private host configuration system.

This repository is intentionally safe to clone and test on a workstation. It
does not apply fleet configuration changes: generated files are rendered only
to operator-chosen staging directories, lifecycle commands emit reviewable
plans, and the current live-operation stubs refuse to run unless invoked as
dry-runs. Runtime rollout remains a separate deployment phase.

The source tree is intentionally free of real site topology. The checked-in
`examples/site-config` tree uses reserved example names and addresses so tests
can validate a complete config without exposing private hostnames, account
inventory, internal addresses, VLAN/interface names, or access policy.

## Layout

- `examples/site-config/`: sanitized example tree mirroring
  `${XDG_CONFIG_HOME:-~/.config}/grafhome-ca`.
- `schemas/`: JSON Schemas for checked-in config, policy, and generated
  lifecycle plan formats.
- `templates/`: non-secret SSH, Apache, systemd, and Smallstep templates.
- `src/`: Rust core APIs and CLIs.
- `scripts/`: release helpers using generated commit-timestamp versions.

## Commands

Validate site policy and config from the default XDG location:

```sh
cargo run --bin grafhome-ca -- check
```

Validate the checked-in example config:

```sh
cargo run --bin grafhome-ca -- check --config-root examples/site-config
```

Run config-only doctor:

```sh
cargo run --bin grafhome-ca -- doctor --config-only
```

Show derived CA endpoints:

```sh
cargo run --bin grafhome-ca -- endpoints
```

Render reviewed deployment files into a staging directory:

```sh
cargo run --bin grafhome-ca -- render --out-dir /tmp/grafhome-ca-render
```

Use `--clean` for rollout staging directories so removed or renamed generated
files cannot linger from a previous render. It removes generated top-level
roots, such as `hosts/`, while preserving unrelated files in the output
directory:

```sh
cargo run --bin grafhome-ca -- render --clean --out-dir /tmp/grafhome-ca-render
```

Preview rendered files without writing:

```sh
cargo run --bin grafhome-ca -- render --out-dir /tmp/grafhome-ca-render --dry-run
```

After CA state has been initialized, export public trust material for private
rollout:

```sh
cargo run --bin grafhome-ca -- export-public --out-dir /tmp/grafhome-ca-public
```

The export bundle contains no secrets: `root_ca.crt`, `root_fingerprint`,
`ssh_host_ca_key.pub`, `ssh_user_ca_key.pub`, `user_ca_keys.pem`,
`ssh_known_hosts`, and `manifest.json`. It may contain private topology in the
CA URL and host certificate principals, so do not commit real export bundles to
this public repo.

Print a local validation-only JSON fixture with JWK placeholders replaced by
deterministic public test provisioners and live CA state paths rewritten to
unusable fixture paths:

```sh
cargo run --bin grafhome-ca -- materialize-test-ca-fixture > /tmp/grafhome-ca-fixture.json
```

During initial CA bootstrap, materialize reviewed runtime JWK provisioners into
the staged `ca.json` after `step ca init` has created the live bootstrap
provisioner and after any additional encrypted JWK keypairs have been generated
under a private operator directory:

```sh
cargo run --bin grafhome-ca -- materialize-runtime-provisioners \
  --live-ca-json /srv/example-ca/step/config/ca.json \
  --staged-ca-json /tmp/grafhome-ca-render/hosts/ca-host/srv/example-ca/step/config/ca.json \
  --jwk-dir /srv/example-ca/secrets/provisioners \
  --out-file /tmp/grafhome-ca-render/hosts/ca-host/srv/example-ca/step/config/ca.json
```

Generate lifecycle plans without executing any commands:

```sh
cargo run --bin grafhome-ca -- plan init-ca
cargo run --bin grafhome-ca -- plan host-bootstrap --host ca-host
cargo run --bin grafhome-ca -- plan create-host-token --host ca-host
cargo run --bin grafhome-ca -- plan enroll-host --host ca-host
cargo run --bin grafhome-ca -- plan host-renew --host ca-host
cargo run --bin grafhome-ca -- plan host-renew-all
cargo run --bin grafhome-ca -- plan backup-ca
cargo run --bin grafhome-ca -- plan proxy-cert
cargo run --bin grafhome-ca -- plan verify-live --host ca-host
cargo run --bin grafhome-ca -- plan create-user-token --user alice --host ca-host
cargo run --bin grafhome-ca -- plan enroll-user --user alice --host ca-host
cargo run --bin grafhome-ca -- plan ssh-ensure --user alice --host ca-host
cargo run --bin grafhome-ca -- plan add-host --host new-host
cargo run --bin grafhome-ca -- plan add-user --user new-user
```

Plans can also be emitted as JSON for tests, scripts, or future executors:

```sh
cargo run --bin grafhome-ca -- plan --json enroll-user --user alice --host ca-host
```

Run the enrollment executor commands after reviewing the corresponding plans:

```sh
# CA origin/operator host.
cargo run --bin grafhome-ca -- ca-fingerprint
cargo run --bin grafhome-ca -- create-host-token --host ca-host
cargo run --bin grafhome-ca -- create-user-token --user alice --host ca-host

# SSH server host root account. Reads the host enrollment token from stdin.
cargo run --bin grafhome-ca -- bootstrap-host-trust
cargo run --bin grafhome-ca -- enroll-host --host ca-host

# User client account. `bootstrap-client` reads the root fingerprint from stdin.
# `enroll-user` reads two stdin lines: the enrollment token, then the
# user-owned refresh password. It prints a pasteable `authorize-user` command
# containing the public renewal JWK for the CA operator.
cargo run --bin grafhome-ca -- bootstrap-client
cargo run --bin grafhome-ca -- enroll-user --user alice --host ca-host
cargo run --bin grafhome-ca -- ssh-ensure --user alice --host ca-host

# CA origin/operator host. Paste the `authorize-user` here-doc printed by
# `enroll-user`; the renewal JWK is public and does not require SSH access from
# the new client to the CA host.
grafhome-ca authorize-user --user alice --host ca-host <<'GRAFHOME_CA_USER_RENEWAL_PUBLIC_KEY'
{"kty":"OKP","kid":"example-public-key"}
GRAFHOME_CA_USER_RENEWAL_PUBLIC_KEY
```

Enrollment secrets default to stdin so tokens and user-owned passwords do not
need to appear in shell history. `enroll-host` reads one line containing the
host token. `enroll-user` reads the user token first and the refresh password
second. `ssh-ensure` reads the refresh password. `authorize-user` reads the
user/client-host public JWK from stdin by default. File overrides exist for automation:
`--token-file`, `--password-file`, `--fingerprint-file`, and `--public-key`.
Smallstep accepts signing tokens only as command arguments, so executor errors
redact token values but process listings can briefly show the child `step`
command while certificate signing is running.

Guarded live-operation stubs:

```sh
cargo run --bin grafhome-ca -- init-ca --dry-run
```

`grafhome-ca init-ca --dry-run` prints the same reviewed initialization plan as
`grafhome-ca plan init-ca`.

This release replaces the old direct `user-login` flow. Site policy should use
the `user_enrollment` provisioner role and point users at that provisioner name;
the examples use `grafhome-user-enrollment`.

`backup-ca`, `proxy-cert`, and `verify-live` are still plans, not live
execution. They exist to keep rollout checklists concrete:

- `backup-ca` emits CA state backup and restore-test commands. The init plan
  includes the same backup/restore-test gate after `step-ca` activation; do not
  bootstrap host trust until that restore test has passed.
- `proxy-cert` emits the proxy TLS certificate issuance shape using the
  configured `proxy_x509` provisioner and the configured
  `GRAFHOME_CA_PROXY_ACME_WEBROOT`.
- `verify-live` emits non-mutating checks for CA health, exported root
  fingerprint consistency, proxy TLS against the exported root certificate,
  OpenSSH server trust, host certificates, and SSH client known-hosts CA
  configuration.

## Release Versioning

Release identity follows the same generated scheme used by `hive-memory` and
`shdeps`:

```text
YYYYMMDD-HHMMSS-<8hex>
```

The timestamp is the UTC commit timestamp. The suffix is the first eight
hex characters of the commit hash. There is no hand-maintained `VERSION` file.

## Site Config

By default, `grafhome-ca` reads site config from:

```text
${XDG_CONFIG_HOME:-~/.config}/grafhome-ca/
  config/deployment.env
  policy/*.tsv
```

The config root can be overridden for tests, examples, or private repos:

```sh
grafhome-ca check --config-root /path/to/site-config
```

Runtime firewall, Apache, systemd, DNS, and SSH server changes are not applied
by this repository until the separate rollout phase is explicitly started.

- Rendered sshd fragments are accompanied by placeholder trust/revocation files
  so installing a reviewed fragment cannot fail because `TrustedUserCAKeys` or
  `RevokedKeys` points at a missing path. Rollout must replace
  `user_ca_keys.pem` with the exported SSH user CA public key before certificate
  auth is expected to work.
- Rendered SSH client fragments point at
  `${GRAFHOME_CA_SSH_TRUST_DIR}/ssh_known_hosts`. Rollout must replace that
  placeholder with the exported host-CA known-hosts file before host
  certificates are expected to verify.
- Rendered sshd fragments include `HostCertificate` for the certificate derived
  from `GRAFHOME_CA_HOST_KEY_PATH`. The host bootstrap plan issues the initial
  host certificate before the fragment should be activated.

No private CA keys, SSH private keys, passwords, provisioner secrets, or tokens
belong in this repo.

Rendered JWK provisioner entries are whole-object
`RUNTIME_SECRET_PLACEHOLDER:*_JSON` markers. Those markers are intentionally not
usable Step provisioners; rollout code must replace each marker with the
complete Smallstep-generated JWK provisioner object, including the public `key`,
`encryptedKey`, and policy-derived claims, during an operator-reviewed
deployment step. Use `materialize-runtime-provisioners` for that deployment
step; it copies the bootstrap JWK object from the live `step ca init` output and
loads any additional encrypted JWK keypairs from the private `--jwk-dir`.

`materialize-test-ca-fixture` is not deployable CA state. It rewrites CA key,
database, SSH CA key, and bind-address fields to fixture-only values, uses
deterministic public JWKs, and omits private JWK material and `encryptedKey` so
tests can validate config shape without checking in provisioner issuance
credentials. Runtime rollout must still replace the placeholders in rendered
deployment files with operator-generated Smallstep provisioner objects.

Lifecycle plans use quoted angle-bracket placeholders for operator-provided
runtime inputs, such as `<public-material-dir>`, `<host-enrollment-token>`,
`<user-enrollment-token>`, `<user-provisioner-public-jwk>`, and
`<user-owned-password-file>`. Replace those with private local values or
automation-provided files during rollout; they are not public repo inputs and
must not contain or expose CA passwords, provisioner secrets, tokens, or
topology-bearing real export bundles.
