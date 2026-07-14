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

Enrollment provisioner private JWKs live only on the CA origin under
`${GRAFHOME_CA_STATE_DIR}/secrets/provisioners`. The corresponding provisioner
objects in `ca.json` contain public verification keys, issuance claims, and
templates, but no `encryptedKey` for the public provisioner API to return.

For an existing CA, upgrade the binary on the CA origin and every enrolled
client before distributing policy that contains the new `renewal_*`,
`allow_effectively_infinite_cert`, `require_ssh_admin_access`, or `ssh_admin`
fields. Old policy remains readable by the new binary, so this binary-first
sequence does not require a flag day. Then run the one-time migration before
installing a newly rendered `ca.json`:

```sh
grafhome-ca migrate enrollment-provisioner-keys
```

The migration preserves each enrollment provisioner's public key, re-encrypts
its private JWK with a fresh independent password, and writes canonical
`.pub.json`, `.priv.json`, and `.password` files. It does not edit `ca.json`, so
existing enrollment tokens remain verifiable until the reviewed config rollout.
It is safe to rerun after completion.

Materialization carries every live device-bound renewal provisioner into the
newly rendered config, preserving its public key and issuance templates while
applying the finite renewal claims. Existing enrolled hosts and users therefore
keep their provisioner names, keys, and renewal credentials. It fails closed
unless both enrollment provisioners have complete encrypted key/password files
whose public material matches the live CA, so a skipped or partial migration
cannot silently disable later approvals.

Treat materialization and installation as one CA maintenance window. The
command takes the same CA lock as approval, revocation, and policy application
while it snapshots live state, but a staged output cannot remain current after
that lock is released. Pause those mutation commands until the materialized
file is installed and the CA is healthy; if live `ca.json` changes meanwhile,
discard the staged output and materialize it again. This prevents an old
snapshot from restoring a revoked renewal provisioner or omitting a newly
approved one.

Materialize reviewed runtime JWK provisioners into the staged `ca.json` after
the migration (or after new bootstrap keys have been generated in the same
private directory):

```sh
cargo run --bin grafhome-ca -- materialize \
  --live-ca-json /srv/example-ca/step/config/ca.json \
  --staged-ca-json /tmp/grafhome-ca-render/hosts/ca-host/srv/example-ca/step/config/ca.json \
  --jwk-dir /srv/example-ca/secrets/provisioners \
  --out-file /tmp/grafhome-ca-render/hosts/ca-host/srv/example-ca/step/config/ca.json
```

Host enrollment uses the same request-and-approval shape as user enrollment:

Before enrollment, install `grafhome-ca` and the Smallstep CLI. Grafhome uses
the standard `step` executable on desktop platforms; Android builds prefer
`step-cli`, the unambiguous name used by Termux's official package. Provision
the private site config under
`${XDG_CONFIG_HOME:-~/.config}/grafhome-ca`. The CA origin additionally needs
the `step-ca` server package. No client CA fingerprint file or previous
Smallstep client state is required: the approved grant carries the CA URL and
root fingerprint, and `grafhome-ca` creates and verifies pinned trust in its
dedicated Smallstep state directory.

On macOS, install `step` with Homebrew as the normal administrator account.
Before root-run host enrollment, install a root-owned copy in the standard
system path; do not run Homebrew as root:

```sh
sudo install -d -o root -g wheel -m 0755 /usr/local/bin
sudo install -o root -g wheel -m 0755 "$(command -v step)" /usr/local/bin/step
```

Privileged operations use the configured `GRAFHOME_CA_ROOT_STEP_BIN` when it is
available, then trusted standard system locations and `PATH`. A root process
rejects a `step` binary, or any directory containing it, when it is writable or
owned by another user. This prevents host enrollment from executing a
user-controlled binary.

```sh
# Target host as root. Leave this running after copying its REQUEST line.
grafhome-ca enroll host

# CA origin as root. Paste the REQUEST, press Enter, approve it, and copy GRANT.
grafhome-ca approve host
```

The target generates its device-bound renewal JWK locally; only its public half
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
of `revoke host` or `revoke user`.

For unattended convergence after a private policy update, run the same command
with scheduled-mode guards:

```sh
grafhome-ca apply host --if-enrolled --quiet
```

An unenrolled host is skipped without output. Routine success and no-op output
are also suppressed, while invalid policy,
unsafe filesystem provenance, `sshd` validation failures, and rollback errors
remain fatal and visible. Sites can enable `require_ssh_admin_access = true`
and mark one or more active users with `ssh_admin = true`; policy validation
then requires every SSH server to retain an active login mapping for at least
one such user.

After changing CA issuance policy, reconcile the live provisioners on the CA
origin:

```sh
# CA origin as root. Dry-run lists provisioners whose managed claims differ.
grafhome-ca apply ca --dry-run
grafhome-ca apply ca
```

`apply ca` updates Grafhome-owned duration and SSH-CA claims. It preserves
provisioner keys, unknown claims, renewal-provisioner restrictions, and
operator-owned provisioners. It also enforces the enrollment provisioners'
X.509-deny and fixed SSH user/host templates. A change is installed with the
same backup, restart, health-check, and rollback path used by enrollment; a
no-op does not restart the CA.

User enrollment requires one public request copied to the CA and one secret
grant copied back. User and host default to the current account and short
hostname, so normal enrollment needs no identity flags:

```sh
# Client host. Enter the renewal password once and leave this running.
# Copy its REQUEST line to the CA, then paste the returned GRANT here.
grafhome-ca enroll user

# CA origin as root. Paste the REQUEST line, press Enter, and approve it.
grafhome-ca approve user

# Rare allowlisted case: issue the initial certificate for roughly 292 years.
# Upgrade grafhome-ca on the target client before approving this grant.
grafhome-ca approve user --effectively-infinite

# Normal use after enrollment.
ssh ca-host
```

If the standard `~/.ssh/id_ed25519` identity already exists, enrollment offers
to use it (the default), replace it, or cancel. Reuse verifies that the public
key matches the private key before creating the Grafhome renewal credential.

Scheduled renewal should run
`grafhome-ca renew host --if-enrolled --if-reachable --quiet` as root and
`grafhome-ca renew user --if-enrolled --if-reachable --quiet` as the enrolled
user. Both commands infer the local identity, skip fresh certificates, and
return successfully without output when enrollment or local renewal material
is absent. `--if-reachable` also skips while a short TCP connection to the
configured CA address cannot be established; configuration, trust, and renewal
errors remain visible. An advisory per-scope lock prevents overlapping renewal
runs. Grafhome's private dotfiles install these jobs hourly. User enrollment
stores the password in macOS Keychain on macOS. On Linux it uses an encrypted
systemd credential and also stores the password in Secret Service when
available. It first attempts a user-scoped credential, supported by systemd 256
and newer. If that is unavailable, `grafhome-ca` falls back to encryption bound
to the machine's TPM without fixed PCR binding, so routine firmware and Secure
Boot database updates do not strand the credential. The user must be able to
open the TPM resource manager; on distributions that restrict `/dev/tpmrm0` to
the `tss` group, add the enrolled user to that group and start a new login
session before enrollment. The
credential file remains owner-only, and copied home-directory data cannot be
decrypted away from the original TPM. `grafhome-ca` tries both formats while
reading, so upgrading systemd does not require reenrollment. It never silently
falls back to a plaintext Linux password file.

On Android/Termux it uses an owner-only file within Termux's app-private data
directory, which Android isolates from other apps and Termux excludes from
Android backup. This Android credential is not separately
application-encrypted; processes already running as the Termux app user can
read it, just as they can use the unencrypted OpenSSH identity stored beside
it. `renew user` reads the corresponding platform store for unattended renewal.
Other deployments must provide equivalent scheduling.

`enroll user` generates the SSH and renewal keys, stores the renewal password,
prints the public request, and waits for the grant. After the grant is pasted,
the same process bootstraps pinned CA trust, obtains the initial certificate,
stores the identity at OpenSSH's standard `$HOME/.ssh/id_ed25519` paths,
verifies renewal, and removes pending state. If any default identity file
already exists, enrollment lists the conflicting paths and asks before
replacing the complete key and certificate set; declining leaves every file
unchanged. A terminated process can resume from pending state by running
`enroll user` again. If the pending request is lost or damaged, run
`enroll user --restart` to rebuild and print it from the existing SSH and
renewal public keys. Host enrollment supports the equivalent root-run
`grafhome-ca enroll host --restart`. Restarting does not replace private keys;
run ordinary enrollment from a fresh state when new keys are required.

File overrides exist for automation:
`--request-file`, `--grant-file`, and `--password-file`; `--request-only` emits
the request without waiting. `approve user --yes` skips operator confirmation.
Pasted requests and grants may include or omit their `REQUEST:` or `GRANT:`
label, and surrounding whitespace is ignored. At an interactive prompt, paste
the REQUEST or GRANT document and press Enter; `Ctrl-D` is not required.
Interactive input bypasses the terminal's canonical line-size limit, so long
single-line grants paste completely on macOS and Linux.
Redirected stdin and file inputs retain read-to-EOF behavior for automation and
formatted multiline documents, and may include copied terminal output around a
labeled document.

Routine user renewal is always bounded by the enrollment provisioner's
`renewal_default_ttl` and `renewal_max_ttl`. An effectively-infinite initial
certificate requires both the explicit `--effectively-infinite` flag and
`allow_effectively_infinite_cert = true` on the exact active user/client-host
policy row. Ordinary `--cert-ttl` values cannot exceed `renewal_max_ttl`.
This exceptional grant uses enrollment document version 2 so an older client
fails safely before issuance instead of replacing the approved certificate
with a routine renewal. The upgraded client preserves the initial certificate
and proves renewal works by writing a temporary certificate. Routine grants
remain version 1 and retain their existing wire format.

An effectively-infinite certificate is a long-lived bearer credential. CA-side
`revoke user` stops future issuance but cannot invalidate a certificate already
accepted by OpenSSH. Use a hardware-backed or otherwise non-exportable SSH key
where the device supports one, and maintain an OpenSSH `RevokedKeys`
distribution path capable of revoking the certificate or its public key
immediately.

CA-side revocation does not require a certificate serial:

```sh
# Disable the host identity and every user enrollment on that host.
grafhome-ca revoke host --host ca-host

# Disable every enrolled client host for a user, or only one client host.
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
succeeds only when the requested host or user-client enrollment is active. Add
`--renewable` to also require the local trust and credential material needed by
a scheduled renewal.

These root-run commands remove the renewal JWK provisioner and immediately stop
future issuance and renewal. OpenSSH does not query step-ca on each login, so a
certificate already issued remains usable until its current expiry. The default
policy lifetimes remain 24 hours for users and 168 hours for hosts.

Enrollment grants are read from stdin so their Smallstep tokens do not appear
in shell history. The public request contains no token, password, or private
key. Smallstep accepts signing tokens only as command arguments, so executor
errors redact token values but process listings can briefly show the child
`step` command while certificate signing is running.

Before `apply`, `approve`, or `revoke` reads policy or performs side effects,
it verifies the filesystem provenance of every config and policy input. Every
lexical path component, symlink, resolved target component, and input file must
be owned by root or the invoking account and must not permit group or world
writes. Root-owned sticky directories such as `/tmp` retain their normal Unix
exception. This accepts protected dot-managed symlinks while preventing another
local account from substituting policy for a privileged invocation. On the
documented root-run workflows, the invoking account is root, so the complete
input chain must be root-owned.

System host lifecycle commands (`enroll host`, `renew host`, and `apply host`)
and CA state commands (`materialize`, `migrate enrollment-provisioner-keys`,
`apply ca`, `approve host`, `approve user`, `revoke host`, and `revoke user`)
enforce an effective UID of root. A non-root invocation fails before reading
enrollment input or changing state. The test suite may exercise these paths
without root only when configuration, CA state, keys, helper tools, and any
redirected installation targets are all confined beneath one protected
temporary sandbox; normal site configuration cannot use that exception.

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
  policy/*.toml
```

The config root can be overridden for tests, examples, or private repos:

```sh
grafhome-ca check --config-root /path/to/site-config
```

Policy files are typed TOML and support comments. Each file has a corresponding
JSON Schema under `schemas/policy/`; see
[`docs/configuration.md`](docs/configuration.md) for the document shape and an
example.

Runtime firewall, Apache, systemd, and DNS changes remain owned by private
configuration management. `enroll host` deliberately installs only the
device-bound OpenSSH files required for certificate operation, validates
`sshd`, and reloads it.

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
complete Smallstep JWK provisioner object, including the public `key`,
policy-derived claims, and issuance templates, during an operator-reviewed
deployment step. `materialize` deliberately omits `encryptedKey`; enrollment
tokens are signed by the root-run CLI using the server-local private JWK and its
independent password.

`materialize-test-ca-fixture` is not deployable CA state. It rewrites CA key,
database, SSH CA key, and bind-address fields to fixture-only values, uses
deterministic public JWKs, and omits private JWK material and `encryptedKey` so
tests can validate config shape without checking in provisioner issuance
credentials. Runtime rollout must still replace the placeholders in rendered
deployment files with operator-generated Smallstep provisioner objects.
