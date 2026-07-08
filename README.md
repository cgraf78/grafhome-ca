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

Preview rendered files without writing:

```sh
cargo run --bin grafhome-ca -- render --out-dir /tmp/grafhome-ca-render --dry-run
```

Print a local validation-only JSON fixture with JWK placeholders replaced by
deterministic public test provisioners and live CA state paths rewritten to
unusable fixture paths:

```sh
cargo run --bin grafhome-ca -- materialize-test-ca-fixture > /tmp/grafhome-ca-fixture.json
```

Generate lifecycle plans without executing any commands:

```sh
cargo run --bin grafhome-ca -- plan init-ca
cargo run --bin grafhome-ca -- plan host-bootstrap --host ca-host
cargo run --bin grafhome-ca -- plan host-renew --host ca-host
cargo run --bin grafhome-ca -- plan host-renew-all
cargo run --bin grafhome-ca -- plan user-login --user alice --device ca-host
cargo run --bin grafhome-ca -- plan add-host --host new-host
cargo run --bin grafhome-ca -- plan add-user --user new-user
```

Plans can also be emitted as JSON for tests, scripts, or future executors:

```sh
cargo run --bin grafhome-ca -- plan --json user-login --user alice --device ca-host
```

Guarded live-operation stubs:

```sh
cargo run --bin grafhome-ca -- init-ca --dry-run
cargo run --bin grafhome-ssh-login -- --dry-run --user alice
```

`grafhome-ca init-ca --dry-run` prints the same reviewed initialization plan as
`grafhome-ca plan init-ca`. `grafhome-ssh-login` is a placeholder for future
user certificate issuance; without `--dry-run` it exits before invoking `step`
or `ssh-agent`, and its dry-run mode currently validates only the CLI surface.

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

No private CA keys, SSH private keys, passwords, provisioner secrets, or tokens
belong in this repo.

Rendered JWK provisioner entries are whole-object
`RUNTIME_SECRET_PLACEHOLDER:*_JSON` markers. Those markers are intentionally not
usable Step provisioners; rollout code must replace each marker with the
complete Smallstep-generated JWK provisioner object, including the public `key`,
`encryptedKey`, and policy-derived claims, during an operator-reviewed
deployment step.

`materialize-test-ca-fixture` is not deployable CA state. It rewrites CA key,
database, SSH CA key, and bind-address fields to fixture-only values, uses
deterministic public JWKs, and omits private JWK material and `encryptedKey` so
tests can validate config shape without checking in provisioner issuance
credentials. Runtime rollout must still replace the placeholders in rendered
deployment files with operator-generated Smallstep provisioner objects.
