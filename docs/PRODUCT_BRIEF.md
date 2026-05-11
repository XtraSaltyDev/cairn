# Product Brief

## Product Name

Cairn

## Tagline

Passwords, recovery, and control in one local vault.

## Product Thesis

Cairn is a local-first password vault for people who want a calmer, more explicit way to store credentials, move gradually from messy password habits, and practice recovery before an emergency. The product should make local control understandable without pretending that forgotten secrets can be recovered by magic.

## Target User

The initial target user is a solo user or small household that wants local control, offline access, clearer recovery, and less dependence on cloud accounts.

## Problem Statement

Users struggle with trust, migration, recovery fear, password chaos, and unsafe sharing. Many password tools either hide too much behind cloud accounts or make recovery feel like an afterthought, leaving users unsure whether they can restore access when a device is lost.

## Core Promise

Store safely, migrate gradually, recover confidently.

## MVP Scope

- Rust core.
- CLI-first workflow.
- Monolithic encrypted vault file.
- Local vault creation and unlock flow.
- Add, get, list, and search basics.
- Password generation.
- Encrypted export.
- Recovery kit guidance.
- Recovery rehearsal.

## Non-Goals

- Sync.
- Browser extension.
- Browser autofill.
- Universal desktop autofill.
- Mobile clients.
- Sharing or collaboration.
- Passkey provider.
- Analytics.

## UX Principles

- One action at a time.
- Explain what is happening.
- Recovery rehearsal is part of setup.
- No false promise of magic account reset.
- Local-first by default.

## P0 Commands

- `init`
- `unlock` or `open` later if needed
- `add`
- `get`
- `list`
- `search`
- `generate`
- `export`
- `recovery-kit`
- `rehearse-recovery`

