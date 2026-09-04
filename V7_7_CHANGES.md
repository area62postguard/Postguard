# PostGuard v7.7 — 7-day subscription trial

- Personal: £49/month after trial.
- Executive: £199/month after trial.
- VIP: £300/month after trial.
- Replaces the no-card standalone demo CTA with a 7-day Stripe subscription trial on every plan.
- Requires a payment method at signup.
- Clearly states automatic monthly billing unless cancelled before the trial ends.
- Adds Stripe Customer Portal access from My Account for subscription management/cancellation.
- Adds signed Stripe webhook handling for subscription lifecycle status updates.
- Registration records Stripe trial status/end date.

## Required new environment variable
POSTGUARD_STRIPE_WEBHOOK_SECRET=whsec_...

Configure the Stripe webhook endpoint as: https://YOUR-PUBLIC-URL/stripe/webhook
Subscribe to customer.subscription.created, customer.subscription.updated, and customer.subscription.deleted.

Important: update all three POSTGUARD_STRIPE_PRICE_* variables to Stripe Price IDs that match £49/£199/£300 in the same Stripe mode as the secret key before testing.
