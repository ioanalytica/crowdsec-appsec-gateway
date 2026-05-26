# crowdsec-appsec-gateway

Minimal HTTP forwardauth → CrowdSec LAPI decisions + AppSec WAF inspection.

CrowdSec ships LAPI (decisions store) and AppSec (real-time WAF) as two
separate components. Most bouncer integrations call one or the other.
This service combines both behind a single `/api/v1/forwardAuth` endpoint
so it can be used from any nginx-style `auth-url` annotation — typically
nginx-ingress, or Traefik's `kubernetesIngressNGINX` provider for
Ingresses on a "nginx-traefik" migration class.

For Traefik-native Ingresses (`class=traefik`), use the
[maxlerebourg plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)
directly — it runs in-process and forwards the request body to AppSec for
full WAF coverage. This gateway exists only to bridge the nginx-style
single-auth-url contract where router.middlewares isn't honoured.

## What it does per request

```
GET /api/v1/forwardAuth   (called by ingress controller as ForwardAuth)
  ├─ extract client IP from X-Forwarded-For (first hop)
  ├─ if IP is in TRUSTED_CIDRS               → 200 (skip CrowdSec)
  ├─ GET LAPI /v1/decisions?ip=<ip>          → 403 if any decision
  ├─ POST AppSec / with X-Crowdsec-Appsec-*  → relay status (200/403)
  └─ fail-open on transport errors           → 200
```

## Install via Helm (OCI)

The chart is published to `oci://ghcr.io/ioanalytica/charts` on tag
release. Reference it from a Flux HelmRelease:

```yaml
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: crowdsec-appsec-gateway
  namespace: crowdsec
spec:
  interval: 1h
  chart:
    spec:
      chart: crowdsec-appsec-gateway
      version: "0.1.0"
      sourceRef:
        kind: HelmRepository
        name: ioanalytica-public   # type: oci, url: oci://ghcr.io/ioanalytica/charts
        namespace: flux-system
  values:
    apiKeySecret:
      name: crowdsec-bouncer-key   # must exist in the release namespace
      key: CROWDSEC_BOUNCER_API_KEY
    env:
      # Defaults already cover localhost + RKE2 pod/service CIDRs
      # (10.42.0.0/16, 10.43.0.0/16). Override if you run a different
      # distribution or have custom cluster CIDRs. Add internal
      # management networks (VPN, bastion subnets, …) here.
      trustedCIDRs:
        - 127.0.0.0/8
        - 10.42.0.0/16             # pod CIDR (RKE2 default)
        - 10.43.0.0/16             # service CIDR (RKE2 default)
        - <YOUR_INTERNAL_NETWORK>
```

## Local smoke-test

```bash
docker run --rm -p 8080:8080 \
  -e LAPI_URL=http://lapi:8080 \
  -e APPSEC_URL=http://appsec:7422 \
  -e API_KEY_FILE=/tmp/key \
  -v <(echo -n "your-api-key"):/tmp/key:ro \
  ghcr.io/ioanalytica/crowdsec-appsec-gateway:0.1.0

curl -sI http://localhost:8080/healthz
curl -sI -H 'X-Forwarded-For: 1.2.3.4' \
        -H 'X-Forwarded-Method: GET' \
        -H 'X-Forwarded-Uri: /.env' \
        -H 'X-Forwarded-Host: example.com' \
        http://localhost:8080/api/v1/forwardAuth
```

## Limitations

nginx-style `auth_request` (and Traefik's `kubernetesIngressNGINX`
translation of `auth-url`) does **not** forward the request body to the
auth server — only headers + URI + method. AppSec therefore sees URL +
headers + method, not POST/PUT body. URL/header-based attacks
(directory traversal, SQLi-in-URL, `.env` probes, etc.) are detected;
POST-body attacks (SQLi in form body, file upload exploits) are not.

For full body inspection use `class=traefik` with the maxlerebourg plugin
inline, which has full request access including body.

## Build & release

Tag a release: `git tag v0.1.1 && git push origin v0.1.1`. The
[docker-build workflow](.github/workflows/docker-build.yml) builds and
pushes:
- `ghcr.io/<owner>/crowdsec-appsec-gateway:<tag>` and `:latest`
- `oci://ghcr.io/ioanalytica/charts/crowdsec-appsec-gateway-<tag>.tgz`

A daily [CVE scan](.github/workflows/cve-scan.yml) runs on the `:latest`
image.

## License

Apache 2.0 — see [LICENSE](LICENSE).
