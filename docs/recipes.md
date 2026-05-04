# Recipes

Common recon patterns and how to run them.

## Find the tenant ID

```bash
entrascout target.com --phases tenant
```

Look for `tenant_id` in the `tenant.json` output.

## Check for ADFS exposure

```bash
entrascout target.com --phases federation
```

Watch for:
- `FED_ADFS_MEX_EXPOSED` → MEX endpoint is public
- `RP catalog leak` → Relying Party list exposed
- `ClaimsXray in production` → debug RP registered

## Enumerate users

```bash
entrascout target.com --phases user_enum --user ceo@target.com
```

Uses `GetCredentialType`, OneDrive timing, and Teams external search.

## Find public Azure blobs

```bash
entrascout target.com --phases azure_resources
```

Deep blob enumeration runs automatically. Check `azure_resources.csv`.

## Check MFA gaps

```bash
entrascout target.com --phases mfa_gaps,auth_surface
```

Looks for:
- Legacy auth banners (SMTP/IMAP/POP3)
- EWS basic auth surface
- ROPC enabled
- ADFS WS-Trust endpoints

## Run authenticated Graph pass

```bash
entrascout target.com --token $GRAPH_TOKEN --phases authenticated
```

Pulls `/me`, org info, Conditional Access policies, MFA report, directory roles.

## Full internal + external

```bash
entrascout target.com --internal --user admin@target.com --token $GRAPH_TOKEN
```

Runs all 52 phases including internal-mode probes.
