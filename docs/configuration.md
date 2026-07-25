# Configuration Reference

All deployment constants use the `GRAFHOME_CA_` prefix. Real deployment config
belongs under `${XDG_CONFIG_HOME:-~/.config}/grafhome-ca/config/deployment.env`
in private site configuration. Derived values are computed by code instead of
being stored independently.

## Local Policy Identity Overrides

`GRAFHOME_CA_LOCAL_HOST` and `GRAFHOME_CA_LOCAL_USER` override operating-system
hostname and account-name inference for commands that operate on the local
identity. They also define the default scope for `status` when it has no
filters; an explicit `status --host` or `status --user` remains a deliberate
query and does not fill the other filter from the environment. The variables
identify the stable policy host and policy user for the machine running
`grafhome-ca`; they do not select a remote SSH destination or login account.
Explicit CLI flags take precedence over these variables.

Set these process environment variables only on systems whose local identities
do not match policy, such as Termux. They are runtime inputs, not
`config/deployment.env` keys. Empty values are ignored.

Termux host lifecycle commands also use the standard `TERMUX_VERSION`, `HOME`,
and `PREFIX` environment to select the app-owned OpenSSH runtime. Host Step
state and the app owner's explicit SSH principals file are derived under
`HOME`; `step-cli`, SSH host keys, trust files, and configuration are derived
under `PREFIX`. Android's system-owned app-data ancestors do not satisfy
OpenSSH's POSIX ownership checks, so the Termux-only fragment disables
`StrictModes`. The backend instead validates the app-owned trees recursively,
rejects symlinks and group- or other-writable paths, and creates the dedicated
principals directories with owner-only permissions. Android's application
sandbox protects the system-owned ancestors. The Termux fragment also sets
`AuthorizedKeysFile none`, so SSH public-key authentication there is CA-only
and cannot bypass these checks through an unrelated static key file. The
site-wide deployment values stay portable and are not rewritten with one
device's application path. Policy host and user names remain site choices; the
Termux backend does not prescribe particular identity values.

## `config/deployment.env`

This file uses literal `KEY=value` lines. It is not shell-sourced; do not quote
values.

Most values are target-host runtime paths. Keys whose names include `ROOT` or
refer to the `grafhome-ca` helper are command-runner paths for root/admin
rollout steps, because live initialization, reconciliation, renewal, and export
plans run with root privileges on the target host. On shdeps-managed hosts where
root uses dotfiles, those tool paths normally live under `/root/.local/bin`.

`GRAFHOME_CA_STATE_DIR`
: Root directory for CA-owned mutable state on the CA host.

`GRAFHOME_CA_SERVER_STEPPATH`
: Root-owned `step` client state for managing the CA from the CA host.

`GRAFHOME_CA_USER_STEPPATH`
: Relative path under a user's home directory for user-level `step` state.

`GRAFHOME_CA_SSH_TRUST_DIR`
: Directory for generated trusted CA public key material.

`GRAFHOME_CA_AUTH_PRINCIPALS_DIR`
: Directory used by `AuthorizedPrincipalsFile` snippets.

`GRAFHOME_CA_PROXY_TLS_DIR`
: Directory for proxy TLS files when rendered for Apache. Proxy certificate
  plans install the exported `root_ca.crt` here so Apache can verify the HTTPS
  CA origin before proxying.

`GRAFHOME_CA_PROXY_ACME_WEBROOT`
: Absolute path to the webroot directory used by `step ca certificate
  --webroot` for proxy X.509 certificate issuance and renewal. The proxy web
  server must serve `${GRAFHOME_CA_PROXY_ACME_WEBROOT}/.well-known/acme-challenge/`
  over HTTP for the `ca_api` DNS name without requiring authentication.

`GRAFHOME_CA_STEP_CA_BIN`
: Absolute path to the `step-ca` server binary.

`GRAFHOME_CA_ROOT_STEP_BIN`
: Preferred absolute path to the `step` client binary. If it is absent,
  `grafhome-ca` checks `/usr/local/bin/step`, `/usr/bin/step`, and `PATH`. The
  selected executable and every parent directory must be owned by root or the
  invoking user and must not be group- or world-writable, except for root-owned
  sticky directories such as `/tmp`. When invoked as root, the complete path
  must be root-owned. On Termux, these checks stop at the validated app-owned
  `PREFIX`; Android's application sandbox protects its system-owned ancestors.
  On macOS, install `step` with
  Homebrew as a normal user and copy it into `/usr/local/bin/step` with root
  ownership for privileged host operations; never run Homebrew as root.

`GRAFHOME_CA_HELPER_BIN`
: Absolute path where the root-run `grafhome-ca` helper is installed. For
  shdeps-managed hosts where root also uses dotfiles, this is normally
  `/root/.local/bin/grafhome-ca`.

`GRAFHOME_CA_HOST_KEY_PATH`
: Absolute path to the SSH host private key used by host certificate renewal.
  The certificate path is derived as `<GRAFHOME_CA_HOST_KEY_PATH>-cert.pub`.
  Rendered sshd fragments reference that derived host certificate path with
  `HostCertificate`.

`GRAFHOME_CA_PASSWORD_FILE`
: Absolute path to the root-readable intermediate CA key password file. The
  file path is non-secret; the password file content must never be committed.
  This path must be inside `GRAFHOME_CA_STATE_DIR` so the `step-ca` service user
  can traverse its parent directories.

Enrollment provisioner credentials are derived rather than configured. For an
enrollment provisioner named `<name>`, the CA origin stores
`${GRAFHOME_CA_STATE_DIR}/secrets/provisioners/<name>.pub.json`,
`<name>.priv.json`, and `<name>.password`. The private JWK and password must be
owner-only regular files, and the enrollment password must differ from
`GRAFHOME_CA_PASSWORD_FILE`. `grafhome-ca migrate enrollment-provisioner-keys`
creates this layout for an existing CA without changing provisioner identities.
Upgrade every policy-consuming binary before distributing policy with the new
renewal, effectively-infinite, or SSH-administrator fields; older binaries
reject unknown policy fields. New binaries continue to accept the previous
policy shape.

`GRAFHOME_CA_SERVICE_USER`
: Unix service account and primary service group that run the CA server.

`GRAFHOME_CA_APACHE_CONF_AVAILABLE`
: Apache `conf-available` directory used by reverse-proxy templates.

## Policy Terms

Policy lives in typed, comment-friendly TOML under `policy/`. The authoring
layout follows the units operators maintain instead of exposing normalized
database-style relations:

- `ca.toml`: keyed CA endpoints and provisioner roles
- `users.toml`: keyed, stable user identities and certificate defaults
- `hosts/<host>.toml`: one complete manifest for each physical machine

The host filename is its stable policy name. Endpoint and provisioner table
keys are their roles, and user table keys are their policy identities, so those
values are not repeated as fields. HTTPS is the only supported endpoint scheme,
and provisioner types are derived from their roles rather than configured. User
principals default to their table keys. TOML comments are supported, booleans
are written as `true` or `false`, endpoint ports are integers, and host
principals and SSH roles are arrays:

```toml
# policy/hosts/server-a.toml
ssh_roles = ["server", "client"]
principals = ["server-a", "server-a.example.test"]

[user_access.alice]
enrollment = true

[[user_access.alice.logins]]
unix_account = "alice"
```

Each host's `user_access` tables colocate two independent capabilities without
combining their meanings. `enrollment` authorizes that user to enroll and renew
on the source host. Each `logins` row authorizes that certificate user to log
into one Unix account on the destination host. Separately, the `client` SSH role
installs outbound host-CA trust. Relationship absence means deny. Lifecycle
status defaults to `active`; write `planned` or `disabled` only when retaining a
future or historical row. A default enrollment uses `enrollment = true`; its
nested table is needed only for non-default options such as
`allow_effectively_infinite_cert` or a non-active status.

Operational inventories such as schedulers, static keys, emergency access, and
CA operators are intentionally outside Grafhome CA policy. The CLI does not
enforce them, so keeping them beside executable authorization policy would give
a misleading impression that changing them affects the CA.

The schemas in `schemas/policy/` validate the complete TOML documents. Canonical
user policy uses `schemas/policy/canonical/users.schema.json`; the original
six-file schema URLs remain compatibility entry points backed by the schemas in
`schemas/policy/legacy/`. Run `grafhome-ca check` after editing policy; commands
that mutate CA or host state also validate policy and its filesystem provenance
before proceeding.

## Migrating Legacy Policy

The compatibility reader accepts the previous normalized `endpoints.toml`,
`hosts.toml`, `users.toml`, `provisioners.toml`, `user-clients.toml`, and
`user-remotes.toml` set during the binary-first migration window. Convert it
without changing the source tree:

```sh
grafhome-ca migrate policy \
  --config-root /path/to/legacy-site-config \
  --out-dir /path/to/review/policy
```

The output directory must not exist. The command writes into a sibling staging
directory, parses and semantically validates every generated document, and
renames the complete directory into place only after validation succeeds. The
writer omits active lifecycle values, keyed identities, derived provisioner
types, and inherited renewal values. An active legacy login with
`allow_ssh = false` becomes a `disabled` historical login because canonical
authorization is expressed by relationship presence and lifecycle state.
Review the generated diff and replace the private policy directory atomically.
The structural conversion does not preserve legacy TOML comments; carry forward
any rationale that remains useful during review. Do not maintain two writable
formats or mix canonical and legacy documents under one config root.

Host-manifest login rows are the sole source of SSH login authorization. Each
active row maps one active policy user's principal to one Unix account on that
host. A user whose `status` is `planned` or `disabled` is omitted from rendered
authorized-principals files even if historical login rows remain active.

`users.toml` may set `require_ssh_admin_access = true` as a durable site safety
switch and designate one or more active users with `ssh_admin = true`. Once
enabled, every host with the `server` SSH role must retain an active
host-manifest login mapping for at least one active SSH administrator.
The separate switch ensures that accidentally deleting every designation is an
error rather than silently disabling the invariant. Policies that omit both
fields retain their existing behavior. The designation does not grant Unix or
sudo privileges; it identifies certificate users whose existing login mappings
serve as the site's administrative recovery path.

`users.<user>.principal`, when it differs from the user table key, and each host
manifest's explicit `principals` own the user and host certificate namespaces.
`grafhome-ca check` rejects duplicate principals, including collisions between
user and host certificates.

`ca_origin`
: The private CA service endpoint hosted on the CA origin host.

`ca_api`
: The client-facing HTTPS endpoint, often reverse-proxied to the CA origin.

`GRAFHOME_CA_API_DNS_NAME`
: Template variable derived from the `ca_api` endpoint `dns_name` field.

`GRAFHOME_CA_ORIGIN_DNS_NAME`
: Template variable derived from the `ca_origin` endpoint `dns_name` field.

`GRAFHOME_CA_ORIGIN_PORT`
: Template variable derived from the `ca_origin` endpoint `port` field.

`GRAFHOME_CA_ORIGIN_ADDRESS`
: Template variable derived from the `ca_origin` endpoint `address` field. The
  step-ca listener binds to this address and port, not to all interfaces.

`GRAFHOME_CA_X509_ALLOWED_DNS_JSON`
: Template variable derived from the `ca_api` and `ca_origin` endpoint
  `dns_name` fields. It renders the authority-level X.509 DNS allow-list used
  by step-ca so the client-facing proxy name and the private backend serving
  name are both explicit issuance policy.

The renderer also derives authority-wide SSH allow-lists directly from active
keyed-user `principal` values and every host manifest's `principals`. These are
generated template variables rather than deployment settings. The CA rejects
SSH user or host principals outside those policy-owned sets even if a
provisioner token or template is misconfigured.

`GRAFHOME_CA_PROVISIONERS_JSON`
: Template variable derived from active `policy/ca.toml` provisioner tables.
  JWK rows render as whole-object runtime placeholders until a deployment step
  replaces them with complete Smallstep provisioner objects containing the
  public `key`, claims, and issuance templates. Private enrollment keys remain
  in the server-local provisioner directory and `encryptedKey` is omitted.
  Non-secret provisioner types that do not require generated key material
  render directly.
  The supported first-bootstrap path is `materialize`: it
  copies public bootstrap state from the live `step ca init` output, loads other
  public JWK files from a private operator directory, and reapplies
  policy-derived claims before the staged `ca.json` is installed.

`GRAFHOME_CA_HOST_CERT_PATH`
: Template variable derived from `GRAFHOME_CA_HOST_KEY_PATH`. It is not stored
  in `deployment.env`.

`user_ca_keys.pem`
: Public trust file exported by `grafhome-ca export` and installed at
  `${GRAFHOME_CA_SSH_TRUST_DIR}/user_ca_keys.pem` for `TrustedUserCAKeys`.

`ssh_known_hosts`
: Public host-CA trust file exported by `grafhome-ca export` and
  installed at `${GRAFHOME_CA_SSH_TRUST_DIR}/ssh_known_hosts` for SSH clients.
  It contains `@cert-authority` entries for managed host certificate
  principals, so real exports can reveal private topology even though they do
  not contain secrets.

`root_fingerprint`
: Public SHA-256 fingerprint of the X.509 root CA certificate. Enrollment
  grants carry it as exactly 64 hexadecimal characters so `grafhome-ca` can
  bootstrap pinned trust internally. A grant's CA URL must exactly match the
  configured `ca_api` URL before bootstrap begins.

`principal`
: A name embedded in an SSH certificate and later matched by OpenSSH policy.

`default_ttl`, `max_ttl`, `renewal_default_ttl`, `renewal_max_ttl`, and `cert_ttl`
: Step duration strings rendered into `ca.json` or used for enrollment. Use
  Go-style `s`, `m`, or `h` units such as `24h`, `168h`, or `720h`; do not use `d`.
  `max_ttl` may be `unlimited` only for the `user_enrollment` provisioner.
  Smallstep requires a positive finite maximum, so Grafhome renders this as
  `2562047h`, the largest whole-hour Go duration (roughly 292 years). The
  configured user `cert_ttl` remains the default lifetime for normal issuance.
  Device-bound renewal provisioners use finite renewal values instead of
  inheriting an unlimited enrollment maximum. Omit a renewal default when it
  matches `default_ttl`, and omit a renewal maximum when the active user policy
  already implies it. Older policy files remain
  readable: an omitted renewal default uses `default_ttl`; when the old
  enrollment maximum is unlimited, the omitted renewal maximum becomes the
  largest finite active-user `cert_ttl` or renewal default. This preserves
  previously valid finite lifetimes without letting inactive historical rows
  inflate routine renewal authority.

`allow_effectively_infinite_cert`
: Optional host enrollment boolean, defaulting to `false`. When true on the
  exact active user/host relationship, a root operator may use `approve user
  --effectively-infinite`. The flag and allow-list entry are both required;
  routine renewal remains finite. Upgrade the target client before issuing this
  exceptional grant. It uses enrollment document version 2 so older clients
  reject it before issuance; ordinary grants remain version 1.
