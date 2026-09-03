# PostGuard v7.0 Production Security Pass

This build implements the code-side production hardening that can be completed without external service accounts or legal approvals.

## Implemented in code
1. Production fails closed when POSTGUARD_SECRET is missing/weak.
2. HSTS, CSP, no-store caching and stronger browser security headers.
3. Email verification flow with expiring one-use verification links.
4. Generic SMTP transactional email support.
5. Admin TOTP MFA using an authenticator app.
6. Security-event logging for login, verification, reset and MFA events.
7. /ready backup + restore confirmation gates.
8. Public Privacy, Terms and Data Retention draft pages.
9. /ready security-test confirmation gate.
10. /ready vision-AI production confirmation gate.
11. /ready social OAuth/publishing production confirmation gate.
12. Production logging plus /health and /ready monitoring endpoints.

## Important
Code cannot truthfully complete external operational obligations by itself. `/ready` returns HTTP 503 in production until backup/restore testing, legal review, security testing, monitoring, real vision AI and social OAuth have each actually been completed and their environment confirmation flag is set to 1.

Do not set a confirmation flag merely to make /ready green.

## First deployment steps
1. Upload app.py, requirements.txt and static/postguard_logo.jpg.
2. Keep DATABASE_URL, POSTGUARD_SECRET and POSTGUARD_ADMIN_EMAIL configured in Render.
3. Add POSTGUARD_ENV=production.
4. Add POSTGUARD_PUBLIC_URL using your real HTTPS site URL.
5. Configure the SMTP variables.
6. Keep POSTGUARD_REQUIRE_ADMIN_MFA=1.
7. Deploy and sign in as Admin. The first production Admin sign-in will require MFA setup.
8. Visit /health (should be 200).
9. Visit /ready. It should remain 503 until the external production tasks are genuinely completed.

## External work still required before commercial launch
- Enable database backups and perform a real restore test.
- Have UK privacy/terms/retention documents legally reviewed and completed with controller/contact details.
- Run an independent application security assessment / penetration test.
- Configure external uptime/error monitoring.
- Integrate and validate an actual image-understanding AI provider.
- Complete official OAuth/app review/API approval for each social network you intend to publish to.

