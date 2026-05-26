"""
CrowdSec AppSec gateway — converts nginx-style /api/v1/forwardAuth calls
into LAPI decision lookup + AppSec WAF inspection.

Used by Traefik's kubernetesIngressNGINX provider (translates the
`nginx.ingress.kubernetes.io/auth-url` annotation into a ForwardAuth
middleware that calls this endpoint).

Flow:
  1. Extract client IP from X-Forwarded-For (first hop).
  2. Skip CrowdSec entirely for cluster-internal CIDRs.
  3. LAPI lookup: any active decision for the IP → return 403.
  4. AppSec inspection: forward URI/method/headers (and body if present)
     to the AppSec endpoint → return AppSec's status (200/403).
  5. Fail-open on transport errors (better than locking everyone out).

NOTE: nginx-style auth_request does NOT forward the request body to the
auth server. The Traefik ForwardAuth translation may or may not — if it
doesn't, AppSec only sees URL+headers+method, not body. POST-body attacks
are not covered by this path. class=traefik with the maxlerebourg plugin
has full body inspection — apps that need WAF on POST bodies should
migrate to class=traefik.
"""
import ipaddress
import json
import os
from typing import List

import httpx
from fastapi import FastAPI, Request, Response


LAPI_URL = os.environ.get("LAPI_URL", "http://crowdsec-service.crowdsec:8080")
APPSEC_URL = os.environ.get(
    "APPSEC_URL", "http://crowdsec-appsec-service.crowdsec:7422"
)
API_KEY_FILE = os.environ.get(
    "API_KEY_FILE", "/secrets/crowdsec/CROWDSEC_BOUNCER_API_KEY"
)
TRUSTED_CIDRS = os.environ.get(
    "TRUSTED_CIDRS",
    # Localhost + RKE2 default pod/service CIDRs. Operators on other
    # distributions or with custom cluster-cidr / service-cidr should
    # override this env var.
    "127.0.0.0/8,10.42.0.0/16,10.43.0.0/16",
).split(",")
TIMEOUT_SECONDS = float(os.environ.get("TIMEOUT_SECONDS", "3"))


with open(API_KEY_FILE) as f:
    API_KEY = f.read().strip()


trusted_networks: List[ipaddress._BaseNetwork] = [
    ipaddress.ip_network(c.strip())
    for c in TRUSTED_CIDRS
    if c.strip()
]


def is_trusted(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in trusted_networks)


client = httpx.AsyncClient(timeout=TIMEOUT_SECONDS)

app = FastAPI()


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.api_route(
    "/api/v1/forwardAuth",
    methods=["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def forward_auth(request: Request) -> Response:
    xff = request.headers.get("x-forwarded-for", "")
    client_ip = (
        xff.split(",")[0].strip()
        if xff
        else (request.client.host if request.client else "")
    )

    # Cluster-internal CIDRs bypass CrowdSec entirely (matches the nginx
    # HCC global-auth-snippet skip and the maxlerebourg plugin's
    # clientTrustedIPs behaviour).
    if is_trusted(client_ip):
        return Response(status_code=200)

    # LAPI decision lookup. Non-empty result list = banned.
    try:
        lapi_resp = await client.get(
            f"{LAPI_URL}/v1/decisions",
            params={"ip": client_ip},
            headers={"X-Api-Key": API_KEY},
        )
        if lapi_resp.status_code == 200:
            try:
                decisions = lapi_resp.json()
            except (ValueError, json.JSONDecodeError):
                decisions = None
            if decisions:
                return Response(status_code=403)
    except httpx.RequestError:
        pass  # fail-open

    # AppSec inspection. Body only present on methods that carry one.
    body = (
        await request.body()
        if request.method.upper() in ("POST", "PUT", "PATCH")
        else b""
    )
    appsec_headers = {
        "X-Crowdsec-Appsec-Ip": client_ip,
        "X-Crowdsec-Appsec-Uri": request.headers.get("x-forwarded-uri", "/"),
        "X-Crowdsec-Appsec-Host": request.headers.get("x-forwarded-host", ""),
        "X-Crowdsec-Appsec-Verb": request.headers.get(
            "x-forwarded-method", "GET"
        ),
        "X-Crowdsec-Appsec-Api-Key": API_KEY,
        "X-Crowdsec-Appsec-User-Agent": request.headers.get("user-agent", ""),
    }
    try:
        appsec_resp = await client.post(
            APPSEC_URL, headers=appsec_headers, content=body
        )
        return Response(status_code=appsec_resp.status_code)
    except httpx.RequestError:
        return Response(status_code=200)  # fail-open
