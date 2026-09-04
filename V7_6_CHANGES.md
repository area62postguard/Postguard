# PostGuard v7.6 — Paid Sign-up Splash

- Added a public `/join` pricing splash page with the PostGuard logo.
- Added three recurring monthly plans: Personal £49, Executive £199, VIP £400.
- Added Stripe Checkout subscription flow. Registration is fail-closed until a completed paid Checkout Session is verified server-side.
- Added `paid_checkouts` records so a successful payment can only be consumed once for registration.
- Registration email is locked to the email used at Stripe Checkout.
- Added subscription fields to customer accounts.
- Added a non-sensitive welcome/subscription email to the new customer with the configured PostGuard admin email copied via CC.
- Verification and password-reset emails are deliberately NOT copied to the admin because they contain private security tokens.
- Existing users continue to sign in normally.

Required Render environment variables:
- POSTGUARD_STRIPE_SECRET_KEY
- POSTGUARD_STRIPE_PRICE_PERSONAL
- POSTGUARD_STRIPE_PRICE_EXECUTIVE
- POSTGUARD_STRIPE_PRICE_VIP

Keep Stripe secrets out of GitHub and chat.
