# Signed file download TCP interruption

On isolated loopback, `download-cut-fixture.py` routes signed gateway `/use` requests through a test-only TCP proxy. The proxy forwards the real authorized request, response headers, and 4096 response-body bytes, then aborts the socket once for the armed operation. The untouched c046 gateway manifest is SHA-256 `c0465afeb10dac4a761b274eb6871a8af750fccc5523a333da2c98dac8b90960`; the served 44da SDK is pinned by SHA-256 `44da83bdccf43a2b36ae4b3f48eaf94fc1006b88180456e26faba61aae344869`. Issuer identity, challenges, signatures, account isolation and gateway authorization are real; all fixture state is disposable. The control endpoint is test-only on loopback.

Two real Chromium runs used random 4 MiB binary data and compared independent WebCrypto SHA-256 digests. A cut of the first binary read left no visible local file, including after closing and reopening the account mirror; an intact retry produced the original hash. After replacing 64 KiB at the server, a cut of a batch-chunk JSON response preserved the previous local bytes and opaque version after mirror reopen; an intact retry produced the replacement hash and a new version. Both cuts reported exactly 4096 response bytes delivered. Failures surfaced as sync errors. This tests process-level mirror reopen, not browser/OS crash, hardware power loss, physical WAN faults, or 128 MiB memory performance. Remote installations may currently be stored as legacy IndexedDB Blobs even with OPFS enabled; this does not qualify a direct-to-OPFS download path.

Run with an available Python environment containing aiohttp, argon2 and cryptography, the verified gateway at `/tmp/codi-beta-batch-mount-built`, and SDK at `/tmp/codi-files-boundary-sdk.mjs`:

```
CODI_SDK=/tmp/codi-files-boundary-sdk.mjs CODI_GATEWAY_BASELINE=/tmp/codi-beta-batch-mount-built python research/opfs-storage/download-cut-fixture.py
# Start a disposable Chromium with remote debugging on loopback port 19293.
NODE_PATH=/path/to/node_modules node tests/mirror-download-tcp-cut.test.cjs
```

The fixture uses ports 19987 and 19988 and requires the Caddy binary at `/tmp/codi-microduck-hosting-evidence/caddy`. It never touches live services.
