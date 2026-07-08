# Architecture

Grafhome CA uses Rust for the core policy APIs and CLIs. Shell remains a thin
adapter layer for release packaging and future host integration points where
the surrounding platform is already shell-based.

Smallstep remains the CA implementation. This project shells out to `step` and
`step-ca` at explicit boundary modules instead of implementing certificate
signing, ACME, OIDC, JWK handling, or SSH certificate wire formats.

## Rust-Owned Responsibilities

- Parse and validate runtime site config from the XDG config root.
- Parse and validate private policy inventories without compiling them into the binary.
- Render non-secret config into a staging directory from typed policy.
- Provide CLIs for validation, lifecycle orchestration, and local cert renewal.
- Keep machine-readable statuses and identifiers centralized.

## Non-Rust Responsibilities

- `step-ca`: CA server and signing authority.
- `step`: Smallstep client operations.
- Apache or another HTTPS reverse proxy: proxy to the CA origin when a site
  chooses that topology.
- Dotfiles cron/systemd: eventual scheduling of renewal commands.
- Shell release scripts: package and smoke-test static release archives.

## Safety Contract

Commands that would mutate CA state, SSH config, firewall rules, DNS, Apache, or
systemd must stay explicitly gated until the rollout phase. The first version of
this repo validates, renders, plans, and packages the intended policy without
modifying fleet systems.

Lifecycle plans are structured data, not execution. They deliberately describe
commands and files that future executors can mock or run behind explicit
operator gates. The `commands` entries are POSIX-shell command lines intended
for an operator shell or a shell-backed executor; non-shell executors must
either invoke them through that contract or grow a structured argv field before
executing plan output directly.

Rendered files are staging artifacts, not an imperative deploy. They must
either contain complete non-secret support files, such as empty revocation
placeholders, or explicitly point at operator-provided runtime secret material.
OpenSSH fragments in particular must not reference missing support files,
because `RevokedKeys` failures can break all public-key authentication.

Plan steps include stable operation/step identifiers and a structured `hosts`
list. Automation should use those machine-readable fields for routing and
policy decisions, not parse human-readable summaries.

Generated plan JSON is validated by `schemas/lifecycle/plan.schema.json`. When
adding a lifecycle operation or step kind, update the Rust constants, schema,
and tests together so future executors get a coherent contract.
