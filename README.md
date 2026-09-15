# PhishingGuard Final

Fresh MSc cybersecurity artefact build.

## Goal
PhishingGuard is a deep-learning phishing risk detection and cyber threat intelligence system. This repository is intentionally built from scratch and kept separate from previous experimental deployments.

## Planned pipeline
Dataset -> reproducible preprocessing -> character-level CNN -> evaluation -> saved model -> FastAPI scanner -> explainable URL/security intelligence -> professional web interface -> local verification -> production deployment.

## Development rules
- Do not fabricate model metrics.
- Keep train/validation/test evaluation reproducible.
- Test locally before deployment.
- Use a single clear ASGI entrypoint (`main:app`).
- Do not modify previous PhishingGuard repositories or deployments.
