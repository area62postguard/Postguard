# PostGuard v7.6.4 — Stripe Checkout CSP fix

- Allows completed PostGuard subscription forms to redirect to Stripe-hosted Checkout by adding `https://checkout.stripe.com` to the CSP `form-action` directive.
- Retains `self` for PostGuard's own forms.
- No Stripe keys, Price IDs, or other secrets are included in this package.
