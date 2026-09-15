# Verified Baseline

PhishingGuard Final currently recovers its scanner and CNN model from the known-good historical commit:

`Vish-Sicario/PhishingGuard@99bb368691442fe3443b9a0cb35ab08302743078`

The baseline is pinned by full commit SHA so changes to the old repository cannot silently alter the final build.

## Protected baseline components

- `app.py` — verified FastAPI phishing scanner
- `phishing_url_detector.keras` — trained character-level CNN URL model
- `requirements.txt` — dependency versions used by the verified deployment

## Final-project rule

Do not edit the historical repository or deployment. New interface and final-project changes belong only in `PhishingGuard-Final` and must be tested before production deployment.

## Next gate

Build this repository in an isolated environment and verify:

1. TensorFlow model loads successfully.
2. `main:app` starts successfully.
3. `/health` responds successfully.
4. Homepage responds successfully.
5. A valid public URL scan completes.
6. Invalid/private URL inputs are rejected safely.

Only after this gate passes should the final website UI be changed.
