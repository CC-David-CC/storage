# Retained legacy backend source

Owner: storage. Legacy admission authority, file-backend management and browser storage staging.

Legacy source only, not a current supported import path or command. Original cross-package namespaces, private imports, target paths, key/account custody, host/network/process actions and fixtures must be ported deliberately before use. Do not add sys.path shims, privileged globals, fake storage or automatic service/firewall actions to make it run. No old module/driver is imported or executed by this extraction; no active backend or minimum dependency changes.

## Source and history

Desktop snapshot `4f72ea86928666189b32f6f05c2c697a37341d06`; exact source baseline `d11ac6c34c8ad40edb945ab9c0b448ddec0c7e01`; separate mechanical merge `0e78618344ed35c163a1f22e999c3cdf11b2a5f8`. Private phase41 retains original/earlier paths, copy-boundary notes and commit/ref maps. No active package/module/test body changed.

| Original path | Retained path |
|---|---|
| `active-system/origin_service/experimental_gateway_admission.py` | `legacy/backend/origin_service/experimental_gateway_admission.py` |
| `active-system/origin_service/files_management.py` | `legacy/backend/origin_service/files_management.py` |
| `active-system/origin_service/public_storage.py` | `legacy/backend/origin_service/public_storage.py` |

These sources remain outside supported package/build/test entrypoints. Existing source baseline failures remain separate; syntax/history checks do not establish old protocol or current application compatibility. Preserve native signed-worker/authorization checks during a real public-interface port. External publication is not authorized by this source retention.
