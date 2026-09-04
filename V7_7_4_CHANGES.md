# PostGuard v7.7.4 — Complimentary Promo Access

- Adds an optional free-access promo field to the public splash page.
- Promo secret is stored only in `POSTGUARD_FREE_ACCESS_CODE` on Render; it is not hard-coded.
- Uses constant-time comparison and rate limits redemption attempts.
- A valid promo code unlocks registration for one hour without Stripe/card details.
- Promo-created users are recorded as `subscription_plan=promo`, `subscription_status=active`.
- Complimentary promo access has no trial expiry and no automatic paid renewal.
- Account and welcome-email wording clearly distinguish promo access from paid recurring subscriptions.
- Current paid trial pricing remains Personal £49/month, Executive £199/month, VIP £300/month after the 7-day free trial.
