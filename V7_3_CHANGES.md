# PostGuard v7.3 changes

- Replaces the prominent raw MFA setup secret with a scannable authenticator-app QR code.
- Uses the standard `otpauth://totp/` format with issuer `PostGuard`.
- Keeps the manual setup key inside a collapsed fallback section.
- Rotates any not-yet-enabled MFA secret once per fresh Admin login session, so a previously exposed setup secret is not reused.
- Keeps the existing 6-digit TOTP verification and production Admin MFA enforcement.
- Adds `qrcode[pil]==8.2` to requirements.
