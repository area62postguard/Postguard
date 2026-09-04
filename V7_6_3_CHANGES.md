# PostGuard v7.6.3

- Fixed the public splash page legal links.
- Terms now uses Flask endpoint `terms_page`.
- Privacy Notice now uses Flask endpoint `privacy_page`.
- Prevents the `/` and `/join` splash pages from raising `werkzeug.routing.exceptions.BuildError`.
