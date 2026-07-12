# Grafhome CA

Grafhome CA is the policy, enrollment, and certificate lifecycle tooling for the
Grafhome SSH certificate authority. The CA cryptographic boundary stays in
Smallstep: `step-ca` runs the server and `grafhome-ca` invokes `step` internally
for client operations. Users and enrollment operators interact through the
`grafhome-ca` CLI rather than running `step` commands themselves.
This repo owns the typed local policy model, schemas, templates, packaging, and
operator commands. Real site policy is loaded at runtime from the XDG config
root and should live in a private repo or private host configuration system.

Generated deployment files are written only to operator-chosen staging
directories. Live mutation is limited to explicit enrollment, approval,
renewal, revocation, and local host-policy application commands. Distribution
of private site config remains owned by the private configuration-management
system.

The source tree is intentionally free of real site topology. The checked-in
`examples/site-config` tree uses reserved example names and addresses so tests
can validate a complete config without exposing private hostnames, account
inventory, internal addresses, VLAN/interface names, or access policy.

## Layout

- `examples/site-config/`: sanitized example tree mirroring
  `${XDG_CONFIG_HOME:-~/.config}/grafhome-ca`.
- `schemas/`: JSON Schemas for checked-in config, policy, and public exports.
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
cargo run --bin grafhome-ca -- render --dry-run
```

After CA state has been initialized, export public trust material for private
rollout:

```sh
cargo run --bin grafhome-ca -- export --out-dir /tmp/grafhome-ca-public
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
cargo run --bin grafhome-ca -- materialize \
  --live-ca-json /srv/example-ca/step/config/ca.json \
  --staged-ca-json /tmp/grafhome-ca-render/hosts/ca-host/srv/example-ca/step/config/ca.json \
  --jwk-dir /srv/example-ca/secrets/provisioners \
  --out-file /tmp/grafhome-ca-render/hosts/ca-host/srv/example-ca/step/config/ca.json
```

Host enrollment uses the same request-and-approval shape as user enrollment:

Before enrollment, install `grafhome-ca` and the Smallstep `step` CLI (commonly
packaged as `step-cli`) and provision the private site config under
`${XDG_CONFIG_HOME:-~/.config}/grafhome-ca`. The CA origin additionally needs
the `step-ca` server package. No client CA fingerprint file or previous
Smallstep client state is required: the approved grant carries the CA URL and
root fingerprint, and `grafhome-ca` creates and verifies pinned trust in its
dedicated Smallstep state directory.

```sh
# Target host as root. Leave this running after copying its REQUEST line.
grafhome-ca enroll host

# CA origin as root. Paste the REQUEST, press Enter, approve it, and copy GRANT.
grafhome-ca approve host
```

The target generates its host-scoped renewal JWK locally; only its public half
leaves the host. After the grant is pasted back, `enroll host` installs the SSH
host certificate and trust configuration, proves JWK renewal works, validates
`sshd`, and reloads it. Scheduled renewal runs `grafhome-ca renew host`; site
policy retains each host's configured renewal owner.

After changing and distributing site policy, preview and activate the affected
host's OpenSSH policy locally:

```sh
# Affected host as root. The hostname is inferred and cannot target another host.
grafhome-ca apply host --dry-run
grafhome-ca apply host
```

`apply host` uses the same validated site model and pinned CA trust as
enrollment. It reconciles only Grafhome-managed OpenSSH files for the local
host, including the dedicated authorized-principals directory, then validates
`sshd` and reloads SSH. A no-op does not reload SSH. If validation or reload
fails, the command restores the previous files and reloads that configuration.
Removing an authorization row therefore removes its stale principals file on
the affected host. This changes login authorization; it does not revoke an
enrollment or an already-issued certificate, which remains the responsibility
of `revoke host` or `revoke user`. Changes to CA issuance policy or an enrolled
identity's certificate principals require the corresponding CA bootstrap,
revocation, or re-enrollment workflow; `apply host` intentionally does not
rewrite live CA state.

User enrollment requires one public request copied to the CA and one secret
grant copied back. User and host default to the current account and short
hostname, so normal enrollment needs no identity flags:

```sh
# Client device. Enter the renewal password once and leave this running.
# Copy its REQUEST line to the CA, then paste the returned GRANT here.
grafhome-ca enroll user

# CA origin as root. Paste the REQUEST line, press Enter, and approve it.
grafhome-ca approve user

# Normal use after enrollment.
ssh ca-host
```

Scheduled renewal should run `grafhome-ca renew host --if-enrolled --quiet` as
root and `grafhome-ca renew user --if-enrolled --quiet` as the enrolled user.
Both commands infer the local identity, skip fresh certificates, and return
successfully without output when enrollment or local renewal material is
absent. Grafhome's private dotfiles install these jobs every eight hours. User
enrollment stores the password in an encrypted systemd user credential for
unattended renewal, in addition to Secret Service when available. Other
deployments must provide equivalent scheduling.

`enroll user` generates the SSH and renewal keys, stores the renewal password,
prints the public request, and waits for the grant. After the grant is pasted,
the same process bootstraps pinned CA trust, obtains the initial certificate,
installs stable `$HOME/.ssh/<user>.key*` aliases, verifies renewal, and removes
pending state. A terminated process can resume from that pending state by
running `enroll user` again. File overrides exist for automation:
`--request-file`, `--grant-file`, and `--password-file`; `--request-only` emits
the request without waiting. `approve user --yes` skips operator confirmation.
Pasted requests and grants may include or omit their `REQUEST:` or `GRANT:`
label, and surrounding whitespace is ignored. At an interactive prompt, paste
the REQUEST or GRANT document and press Enter; `Ctrl-D` is not required.
Redirected stdin and file inputs retain read-to-EOF behavior for automation and
formatted multiline documents, and may include copied terminal output around a
labeled document.

CA-side revocation does not require a certificate serial:

```sh
# Disable the host identity and every user device enrolled on that host.
grafhome-ca revoke host --host ca-host

# Disable every enrolled device for a user, or only one device.
grafhome-ca revoke user --user alice
grafhome-ca revoke user --user alice --host laptop-a
```

Inspect live enrollment state from the CA or an enrolled client. The command
queries the CA's public provisioner API through the locally pinned trust root;
it does not read `ca.json` directly:

```sh
grafhome-ca status --host ca-host
grafhome-ca status --user alice
grafhome-ca status --user alice --host laptop-a
```

Add `--quiet` to suppress output and use the exit status as a predicate. It
succeeds only when the requested host or user-device enrollment is active. Add
`--renewable` to also require the local trust and credential material needed by
a scheduled renewal.

These root-run commands remove the scoped JWK provisioner and immediately stop
future issuance and renewal. OpenSSH does not query step-ca on each login, so a
certificate already issued remains usable until its current expiry. The default
policy lifetimes remain 24 hours for users and 168 hours for hosts.

Enrollment grants are read from stdin so their Smallstep tokens do not appear
in shell history. The public request contains no token, password, or private
key. Smallstep accepts signing tokens only as command arguments, so executor
errors redact token values but process listings can briefly show the child
`step` command while certificate signing is running.

This release replaces the old direct `user-login` and shared SSHPOP renewal
flows. Site policy should use
the `user_enrollment` provisioner role and point users at that provisioner name;
the examples use `grafhome-user-enrollment`.

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

Runtime firewall, Apache, systemd, and DNS changes remain owned by private
configuration management. `enroll host` deliberately installs only the scoped
OpenSSH files required for certificate operation, validates `sshd`, and reloads
it.

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
  from `GRAFHOME_CA_HOST_KEY_PATH`. `enroll host` issues the initial host
  certificate before activating that fragment.

No private CA keys, SSH private keys, passwords, provisioner secrets, or tokens
belong in this repo.

Rendered JWK provisioner entries are whole-object
`RUNTIME_SECRET_PLACEHOLDER:*_JSON` markers. Those markers are intentionally not
usable Step provisioners; rollout code must replace each marker with the
complete Smallstep-generated JWK provisioner object, including the public `key`,
`encryptedKey`, and policy-derived claims, during an operator-reviewed
deployment step. Use `materialize` for that deployment
step; it copies the bootstrap JWK object from the live `step ca init` output and
loads any additional encrypted JWK keypairs from the private `--jwk-dir`.

`materialize-test-ca-fixture` is not deployable CA state. It rewrites CA key,
database, SSH CA key, and bind-address fields to fixture-only values, uses
deterministic public JWKs, and omits private JWK material and `encryptedKey` so
tests can validate config shape without checking in provisioner issuance
credentials. Runtime rollout must still replace the placeholders in rendered
deployment files with operator-generated Smallstep provisioner objects.
