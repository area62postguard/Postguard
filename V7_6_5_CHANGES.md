# PostGuard v7.6.5 — 7-Day Free Demo

## Added
- New **7-Day Free Demo** option on the public splash/pricing page.
- Demo registration requires no Stripe payment or card details.
- Demo users still use the normal secure account creation and email-verification flow.
- Demo access lasts exactly 7 days from account creation.
- One demo is allowed per email address.
- Demo accounts are marked `subscription_plan=demo` and `subscription_status=trialing`.
- New `trial_ends_at` user field and `demo_trials` table.
- Expired demo accounts are blocked from protected PostGuard features and directed back to the pricing page.
- Existing demo customers can purchase a paid plan with the same email; verified Stripe payment upgrades the existing account instead of creating a duplicate account.
- Demo welcome email confirms that no payment was taken and explains the 7-day limit.

## Existing paid flow
The Personal, Executive and VIP Stripe Checkout paths remain unchanged. The Stripe Checkout CSP fix from v7.6.4 is retained.

## Important
Stripe subscription lifecycle webhooks are still required before commercial production launch so cancellations, failed renewals and other subscription state changes remain synchronized with PostGuard.
