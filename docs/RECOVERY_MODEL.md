# Recovery Model

## Recovery Promise

No backdoors. No account reset. Your recovery path only works if you prepare it.

Cairn must be explicit about recovery because local-first control shifts responsibility to the user. A forgotten passphrase or missing recovery material can mean permanent lockout.

## Three Layers

Recovery depends on three separate layers:

- Access to the app.
- Access to the encrypted data.
- Access to the secret needed to decrypt it.

Having the app is not enough. Having a vault file is not enough. Recovery requires the correct encrypted data and the required recovery material.

## Recovery Package

A usable recovery package should include:

- Working local vault.
- Portable encrypted backup or export.
- Recovery kit stored separately from the device.

## Standard Recovery Mode

In standard recovery mode, the user stores recovery kit material and the master passphrase or approved recovery material somewhere safe and separate from the device. Cairn should guide the user through setup and make the limits clear.

## High-Risk Recovery Mode

Some users may refuse to write down a passphrase or recovery material. Cairn can allow that choice only with clear language about the increased lockout risk. The product must not imply that support, an account reset, or hidden recovery service can restore access later.

## Restore Rehearsal

The user should prove they can locate backup and recovery materials and complete a mock restore before setup is considered complete. A restore rehearsal should verify the process without exposing secrets in logs, examples, screenshots, or telemetry.

## User-Facing Copy Snippets

> Create your recovery kit before you need it.

> A backup you have never tested is not a recovery plan.

> Cairn cannot recover a vault without the required recovery material.

