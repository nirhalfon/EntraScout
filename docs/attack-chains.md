# Attack Chains

EntraScout doesn't just list findings — it **chains them** into multi-step attack paths.

## How it works

1. Every `Finding` has `ChainTag` values (e.g. `FED_ADFS_MEX_EXPOSED`)
2. `TAG_ENABLES` maps each tag to attack primitives (e.g. `forge-saml-token`)
3. `ATTACK_PATHS` templates define multi-step paths with `needs` tags
4. If all tags in a path are present, the path is **triggered**

## Example: Golden SAML

```
FED_ADFS_DETECTED  →  FED_ADFS_MEX_EXPOSED
                              ↓
                    forge-saml-token
                              ↓
                    golden-saml-attack
```

## Attack Path Templates

| Path | Required Tags |
|---|---|
| Golden SAML via ADFS | `FED_ADFS_DETECTED`, `FED_ADFS_MEX_EXPOSED` |
| Legacy-auth password spray | `USER_ENUM_GETCREDTYPE`, `LEGACY_AUTH_EWS_BASIC` |
| Device-code phishing | `DEVICE_CODE_FLOW`, `USER_ENUM_TEAMS` |
| Public blob exfil | `AZ_BLOB_PUBLIC_LISTING` |
| Dataverse unauth read | `PP_POWER_PAGES_ODATA` |

## Output

Attack chains are rendered as:

- **Mermaid diagrams** in `attack_paths.md`
- **Interactive D3 graph** in the web UI
- **MITRE ATT&CK technique IDs** per tag
