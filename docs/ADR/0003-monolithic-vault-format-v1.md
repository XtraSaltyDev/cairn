# ADR-0003: Monolithic vault format v1

## Status

Accepted for MVP design

## Decision

Use a monolithic encrypted snapshot format for CVF-1.

## Rationale

- Easier to reason about.
- Easier backup and restore story.
- Smaller metadata surface.
- Better for first security learning milestone.

## Tradeoffs

- Full-file rewrite on change.
- Poor incremental sync story.
- Corruption blast radius must be mitigated with atomic writes and backups.

## Consequences

Future append-only or per-record format is deferred until sync or sharing exists.

