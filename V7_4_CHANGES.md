# PostGuard v7.4

## Privacy and retention hardening

- Replaced the placeholder `/privacy` page with a UK-focused launch-draft Privacy Notice.
- Added the agreed 16+ minimum account age wording.
- Uses `security@postguard.uk` as the public privacy/security contact.
- Documents contract, legitimate interests, consent and legal-obligation lawful-basis structure.
- Documents scan content, images, metadata, risk scoring and decision-support limitations.
- States that customer posts, images and scan content are not used to train AI models.
- Documents service providers, international-transfer safeguards, user rights, opt-in marketing and ICO complaints.
- Expanded `/data-retention` with the agreed 12-month security-event retention policy.
- Added automatic pruning of security events older than 365 days when security events are recorded.
- Account deletion and Admin customer deletion now remove `auth_tokens` as well as existing customer-owned records.
- Security events remain subject to the 12-month security-log policy rather than being erased with ordinary workspace data.
- Added Privacy/Terms links to registration/login and Privacy/Retention/Terms links to My Account.
- Health/readiness version updated to 7.4.

## Important

The legal pages remain launch drafts. `POSTGUARD_LEGAL_REVIEW_CONFIRMED` must remain false until qualified UK legal/privacy counsel has reviewed and approved the production documents and operating model.
