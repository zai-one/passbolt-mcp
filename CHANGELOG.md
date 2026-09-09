# Changelog

## 0.2.0

- Explicit config-file startup and offline configuration doctor.
- Install/client guide, local setup wizard and clean-wheel validation.
- Isolate active GPG keyrings without copying agent sockets; stop the private runtime agent on close. Support MSYS GnuPG paths on Windows.
- Passwords remain in server custody. GnuPG must be installed separately. Real disposable-key crypto tests run in the Linux gate. Secret producer and automatic unknown-write reconciliation are future work.
- LicenseRef-ZAI-ONE and Issues-based feedback policy.
