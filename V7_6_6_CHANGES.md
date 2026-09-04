# PostGuard v7.6.6 — Email verification redirect fix

- After a valid verification link is clicked, PostGuard now clears any stale pre-verification session and sends the customer directly to the sign-in page.
- Uses an explicit HTTP 303 redirect to `/login?verified=1` after verification.
- Shows: **Email verified successfully. Sign in to start your 7-day PostGuard demo.**
- Keeps the v7.6.5 7-day free demo flow and existing Stripe checkout changes intact.
