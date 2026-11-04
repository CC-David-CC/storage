# Signed file download TCP interruption

On isolated loopback, `download-cut-fixture.py` routes signed gateway `/use` requests through a test-only TCP proxy. The proxy forwards the real authorized request, response headers, and 4096 response-body bytes, then aborts the socket once for the armed operation. The untouched c046 gateway manifest is SHA-256 `c0465afeb10dac4a761b274eb6871a8af750fccc5523a333da2c98dac8b90960`; the served 44da SDK is pinned by SHA-256 `44da83bdccf43a2b36ae4b3f48eaf94fc1006b88180456e26faba61aae344869`. Issuer identity, challenges, signatures, account isolation and gateway authorization are real; all fixture state is disposable. The control endpoint is test-only on loopback.

Two real Chromium runs used random 4 MiB binary data and compared independent WebCrypto SHA-256 digests. A cut of the first binary read left no visible local file, including after closing and reopening the account mirror; an intact retry produced the original hash. After replacing 64 KiB at the server, a cut of a batch-chunk JSON response preserved the previous local bytes and opaque version after mirror reopen; an intact retry produced the replacement hash and a new version. Both cuts reported exactly 4096 response bytes delivered. Failures surfaced as sync errors. This tests process-level mirror reopen, not browser/OS crash, hardware power loss, physical WAN faults, or 128 MiB memory performance. With the OPFS backend enabled on source 30f6f80ef, direct IndexedDB inspection confirmed the cold and replacement files hold codi-opfs-content/1 references with matching sizes and hashes; interrupted replacement retains the previous generation. The SDK first receives and verifies a Blob before the mirror captures it into OPFS, so this is not a streaming direct-to-OPFS download or a bounded total-memory claim.

Run with an available Python environment containing aiohttp, argon2 and cryptography, the verified gateway at `/tmp/codi-beta-batch-mount-built`, and SDK at `/tmp/codi-files-boundary-sdk.mjs`:

```
CODI_SDK=/tmp/codi-files-boundary-sdk.mjs CODI_GATEWAY_BASELINE=/tmp/codi-beta-batch-mount-built python research/opfs-storage/download-cut-fixture.py
# Start a disposable Chromium with remote debugging on loopback port 19293.
NODE_PATH=/path/to/node_modules node tests/mirror-download-tcp-cut.test.cjs
```

The fixture uses ports 19987 and 19988 and requires the Caddy binary at `/tmp/codi-microduck-hosting-evidence/caddy`. It never touches live services.

`tests/mirror-download-browser-kill.test.cjs` additionally SIGKILLs a real Chromium browser after each failed socket-interrupted download, restarts Chromium with the same persistent profile, and signs in again. After the cold failure the file was still absent; after the replacement failure the prior bytes and exact version remained, and a verified retry produced the new hash. The process was killed after the failed transfer, not at an arbitrary instruction during publication, and this does not establish OS crash or power-loss durability. The first attempted test stored its username only in localStorage immediately before SIGKILL; it could not sign back in after restart, so the corrected test passes test credentials through the external harness instead.
