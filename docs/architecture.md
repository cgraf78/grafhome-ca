# Architecture

Grafhome CA uses Rust for the core policy APIs and CLIs. Shell remains a thin
adapter layer for release packaging and future host integration points where
the surrounding platform is already shell-based.

Smallstep remains the CA implementation. This project shells out to `step` and
`step-ca` at explicit boundary modules instead of implementing certificate
signing, ACME, OIDC, JWK handling, or SSH certificate wire formats.

## Rust-Owned Responsibilities

- Parse and validate runtime site config from the XDG config root.
- Parse and validate the private site policy without compiling it into the binary.
- Render non-secret config into a staging directory from typed policy.
- Export public CA trust material from initialized Smallstep state for reviewed rollout.
- Provide CLIs for validation, policy-controlled enrollment, renewal, and revocation.
- Keep machine-readable statuses and identifiers centralized.

The host-centric TOML documents are an authoring projection, not the runtime
domain model. Loading derives stable names from map keys and host filenames,
then normalizes CA settings, identities, hosts, enrollments, and login
relationships into one typed `Policy`. Every renderer and authorization path
consumes that model. The legacy compatibility reader and canonical reader
therefore share semantic validation instead of maintaining parallel policy
implementations.

## Non-Rust Responsibilities

- `step-ca`: CA server and signing authority.
- `step` (or Termux's `step-cli` package): Smallstep client operations.
- Apache or another HTTPS reverse proxy: proxy to the CA origin when a site
  chooses that topology.
- Dotfiles cron/systemd: scheduling idempotent host and user renewal commands.
- Shell release scripts: package and smoke-test platform release archives,
  including Android/Bionic aarch64 builds for Termux.

Hosted Linux CI checks Android archives structurally (AArch64 ELF plus the
Bionic interpreter). A separate x86_64 Android build runs `check` against the
public fixture tree inside the official Termux app, while the AArch64 release
artifact retains structural cross-build coverage.

## Safety Contract

Enrollment and identity revocation are the narrow live-mutation boundary.
`approve user` and `approve host` install device-bound renewal JWK provisioners
on the CA origin and roll back if CA activation or health verification fails.
Private JWK material never leaves its enrolled host. Successful approval also
records the SSH public key and canonical renewal public JWK in an owner-only,
untracked registry on the CA origin. Routine renewal does not depend on that
registry. Existing deployments backfill it by exporting target-local public
material. Import verifies the live renewal JWK, binds the legacy provisioner's
SSH template to the asserted key, and activates the registry only after a
restart and health check. `revoke user` and `revoke host` use the registry to
remove those provisioners and append exact plain public keys plus renewal JWK
fingerprints to private tracked policy, without certificate serial lookup.
Revoked registry and tracked records remain permanent tombstones, so a logical
identity can be reused only with new SSH and renewal keys.

OpenSSH does not perform online CA revocation checks. Host policy application
therefore compiles the tracked user keys into the server-side `RevokedKeys` KRL
and tracked host keys into the client-side `RevokedHostKeys` KRL. Revoking a
plain key also rejects certificates renewed later for that key. KRL generation
and validation occur before live writes; SSH configuration validation and
reload share the existing rollback transaction. The tracked policy update is
written before CA activation so a failed revoke can leave only a conservative,
retryable state.
The two broad enrollment provisioners keep only their public JWKs in `ca.json`.
Their encrypted private JWKs and independent passwords are server-local inputs
to operator token creation, so `/provisioners` cannot publish an offline
password-cracking target. Enrollment provisioners deny X.509 issuance and force
the intended SSH certificate type. Device-bound renewal provisioners pin exact
principals and the enrolled SSH public key, deny X.509 issuance, and enforce
finite renewal claims. The broad enrollment issuers compare the requested SSH
key with a signed custom token claim, so initial issuance is key-bound too.
Authority-wide SSH allow-lists provide a final policy check over all configured
user and host principals.
Routine user enrollment grants retain document version 1. An exceptional
effectively-infinite grant uses version 2, which makes pre-feature clients fail
before issuance. A compatible client preserves that initial certificate and
tests the finite renewal path with temporary output. This version boundary is
deliberate because silently treating the exceptional grant as routine would
replace the operator-approved certificate.
Enrollment grants are bound to the requesting host's keys and the configured
`ca_api` URL. Their root fingerprints use the fixed SHA-256 hexadecimal form;
the copied grant remains the out-of-band trust handoff for first bootstrap.
`enroll host` installs only host-specific SSH trust/configuration after issuing
the host certificate, validates JWK renewal and `sshd`, and reloads it. Broader
firewall, DNS, Apache, CA initialization, backup, and fleet rollout changes
remain owned by private configuration management and explicit operator runbooks.

Rendered files are staging artifacts, not an imperative deploy. They must
either contain complete non-secret support files, such as plain revocation key
sources, or explicitly point at operator-provided runtime secret material.
OpenSSH fragments in particular must not reference missing support files,
because `RevokedKeys` failures can break all public-key authentication.
`HostCertificate` is the deliberate exception: it points at the runtime host
certificate generated by `enroll host` or `renew host`, so the certificate must
exist before the fragment is activated.
Rollout staging should use `render --clean` or a fresh output directory so stale
files from previous renders cannot be installed accidentally. Clean renders
remove generated top-level roots, such as `hosts/`, rather than deleting every
child in the staging directory.

`export` is a read-only bridge from initialized Smallstep state to
rollout inputs. It reads the root certificate and SSH CA public keys, computes
the root fingerprint with the configured `step` binary, and emits a no-secret
bundle whose manifest is validated by
`schemas/public/export-manifest.schema.json`. The bundle is still
topology-bearing because it includes the CA URL and host certificate
principals, so real exports belong in private rollout state and must not be
committed to the public repository. The command must never read from
`step/secrets` or export provisioner tokens, encrypted JWKs, passwords, or
private keys.

Privileged CA mutation commands run only as root on the configured physical CA
origin. The origin check uses the kernel hostname rather than the policy
identity override used by local host/client commands. Approval reserves the
registry record before activating step-ca; import, approval, and revocation all
hold the CA mutation lock while reconciling live state.
