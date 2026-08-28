# PostGuard Production v1

Production-oriented foundation for the PostGuard executive digital-exposure protection platform.

Includes:
- Organisation-scoped users and principals
- Role-based access foundation
- Password hashing
- Hardened sessions and security headers
- MFA integration point
- Secure image upload size/type checks
- Caption and image-metadata risk analysis
- Alerts, cases, principals and audit log
- Responsive phone/laptop dashboard
- Gunicorn/Docker deployment configuration

Demo login:
demo@postguard.local
ChangeMe123!

Before real client data, replace the demo MFA gate with WebAuthn/TOTP or a managed identity provider, move the database to PostgreSQL, use encrypted private object storage, add malware scanning/CSRF/rate limiting/password recovery, configure secrets management, retention/deletion, monitoring, GDPR controls and independent penetration testing.

Monitoring should use official/licensed APIs and public or client-authorised data only.
