# Security Policy

## Scope and intent

wp-sentinel is a **detection-only** tool for authorised security testing. It
observes; it does not exploit. Contributions and reports are held to that line.

## Reporting a vulnerability in wp-sentinel

Email **henrry.220267@gmail.com** with `SECURITY` in the subject, or open a
[private advisory](../../security/advisories/new). Please don't open a public
issue for anything exploitable.

I'll acknowledge within 72 hours.

## What counts as a security issue here

- A check that performs an **exploitative** action — sending credentials, a
  payload, a `system.multicall`, anything that acts on the target rather than
  observing it. This tool must never do that, so a check that crosses the line
  is a defect regardless of how useful the result would be.
- A check reporting a **false clean** — saying a site is fine when the
  misconfiguration it looks for is present. A false all-clear is worse than no
  check, because it tells an operator to stop looking.
- Command or SSRF injection through a target value that reaches a subprocess or
  an internal request.

## What does not

- False **positives** (a check firing on a hardened site). Still worth an
  issue, just not a security one.
- The fact that the tool can be pointed at a site you do not own. The
  authorisation gate is a deterrent and a statement of intent, not an access
  control — misuse is on the user, and that is true of every scanner.

## Responsible use

Do not use wp-sentinel against systems you do not own or lack written
permission to test. Doing so may be illegal. The maintainers accept no
liability for misuse.
