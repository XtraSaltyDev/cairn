# ADR-0002: Rust core and CLI-first MVP

## Status

Accepted

## Decision

Start with Rust core and CLI-only MVP.

Desktop UI is deferred until the core format and tests stabilize.

## Rationale

- Smallest attack surface.
- Fastest path to format correctness.
- Best review boundary for Codex-generated code.
- Keeps crypto/security logic separate from presentation.

## Alternatives Considered

- Minimal Tauri UI now.
- Full desktop app now.
- Electron/TypeScript app.
- Sync-ready append-only design.

## Consequences

CLI is not the final user experience.

UX language and recovery flows are still designed in docs.

Minimal Tauri may be added later as a thin shell.

