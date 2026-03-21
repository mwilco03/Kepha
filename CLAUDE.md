# Gatekeeper Development Standards

## No Shell-Outs — Hard Standard

**NEVER shell out to external commands for functionality we control.**

This is a non-negotiable architectural rule. We own our code. Shelling out is:

1. **Fragile** — string building for command arguments breaks silently when formats change
2. **A security risk** — command injection, PATH manipulation, argument escaping bugs
3. **Uncontrollable** — when we call an external binary, we lose ownership of what happens

If we control the API or have a library binding (e.g., `google/nftables` netlink),
we use the internal call. We own what happens.

### Applies to:
- **nftables**: Use `github.com/google/nftables` netlink library, never `exec.Command("nft", ...)`
- **Network configuration**: Use netlink (`vishvananda/netlink` or equivalent), never `ip` command
- **System operations**: Prefer Go syscalls and libraries over shelling out to utilities
- **Any new integration**: Always look for a Go library or syscall first

### Exceptions (require explicit justification in code comments):
- Third-party daemons that must be managed via their CLI (e.g., `dnsmasq`, `suricata`)
- One-time system queries where no Go library exists

## Active Countermeasures — Disabled by Default

Active countermeasures (tarpit, latency injection, bandwidth throttle, RST chaos,
SYN cookie enforcement, TTL randomization) are **disabled by default** and require
a **deliberate action** to enable:

- The `Countermeasures` engine starts in disabled state (`Enabled: false`)
- Policies can be defined while disabled, but no rules are enforced until explicitly enabled
- Enabling requires calling `Enable()` — there is no auto-enable path
- This prevents accidental enforcement of aggressive network countermeasures

## Punchlist — Read Before Every Session

**Check `PUNCHLIST.md` at the start of every session.** It contains prioritized findings from a multi-agent review (Security Engineer, Network Engineer, Frontend Developer, UX Architect, Reality Checker). Work items top-down by severity: Critical first, then High, then Medium.

Mark items `[x]` in PUNCHLIST.md as you complete them. Do not skip severity levels.

## Security Is Non-Negotiable

**NEVER remove, downgrade, bypass, or weaken security to make something work.**

- If auth is broken, fix auth — don't disable it
- If CSP blocks scripts, vendor the scripts — don't remove CSP
- If TLS causes issues, fix the cert — don't fall back to HTTP
- If rate limiting interferes with testing, fix the test — don't remove the limiter
- If RBAC is in the way, configure it correctly — don't switch to a weaker auth model
- Difficulty is not a reason to weaken security. Ever.

Any commit that weakens security posture will be reverted.
