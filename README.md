# PostGuard v4 — Intelligence MVP

## Run
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py

Open http://127.0.0.1:5000

Demo login:
demo@postguard.local
ChangeMe123!

## v4 features
- Authenticated security workspace
- Pre-publication scanner
- Caption exposure engine
- Image metadata/GPS inspection
- Explainable risk score
- Principal management
- Alert queue
- Security cases
- Audit log
- Authorised monitoring source registry
- Production connector architecture point
- Responsive dashboard
- Docker-ready structure

## AI/monitoring architecture
The UI and API are separated so a production deployment can attach:
1. Computer vision/OCR provider
2. Redaction/suggestion service
3. Official social platform APIs
4. Licensed social-listening provider
5. Public-web/brand monitoring
6. Threat/breach notification provider

No private-account bypassing, covert surveillance or restricted scraping is implemented.

## Production requirements before real client data
MFA/SSO, RBAC, PostgreSQL, encrypted object storage, KMS, CSRF protection, secure cookies, rate limiting, malware scanning, tenant isolation, retention/deletion controls, GDPR/DPIA, secrets management, monitoring/backups and independent penetration testing.
