#!/usr/bin/env python3
"""Mint Actions OIDC JWT and probe whether GitHub-owned RPs accept it.
Never writes JWT to artifacts; only status codes + claim summary.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

REQUESTS_TIMEOUT = 20


def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_claims(jwt: str) -> dict[str, Any]:
    parts = jwt.split(".")
    if len(parts) < 2:
        raise ValueError("not a jwt")
    return json.loads(b64url_decode(parts[1]))


def mint_oidc(audience: str) -> tuple[str | None, dict[str, Any]]:
    req_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    req_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not req_url or not req_token:
        return None, {"error": "missing ACTIONS_ID_TOKEN_REQUEST_* env (not on Actions?)"}
    url = req_url + ("&" if "?" in req_url else "?") + "audience=" + urllib.parse.quote(audience, safe="")
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {req_token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUESTS_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
            token = body.get("value") or body.get("token")
            if not token:
                return None, {"error": "no token in response", "keys": list(body.keys())}
            return token, {"status": "ok"}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")[:500]
        return None, {"error": f"HTTP {e.code}", "body": err_body}
    except Exception as e:
        return None, {"error": str(e)[:300]}


def http_probe(url: str, headers: dict[str, str], method: str = "GET", data: bytes | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=REQUESTS_TIMEOUT) as resp:
            body = resp.read(800)
            return {
                "url": url,
                "method": method,
                "status": resp.status,
                "content_type": resp.headers.get("Content-Type"),
                "body_snip": body.decode(errors="replace")[:400],
            }
    except urllib.error.HTTPError as e:
        body = e.read(800)
        return {
            "url": url,
            "method": method,
            "status": e.code,
            "content_type": e.headers.get("Content-Type") if e.headers else None,
            "body_snip": body.decode(errors="replace")[:400],
        }
    except Exception as e:
        return {"url": url, "method": method, "status": 0, "error": str(e)[:300]}


def probe_with_token(jwt: str, audience: str) -> list[dict[str, Any]]:
    """Attempt OIDC JWT as Bearer against GitHub surfaces. Non-destructive GETs only."""
    auth = {"Authorization": f"Bearer {jwt}", "Accept": "application/json", "User-Agent": "oidc-rp-probe-h1"}
    auth_token = {"Authorization": f"token {jwt}", "Accept": "application/json", "User-Agent": "oidc-rp-probe-h1"}
    results = []

    # GitHub REST
    results.append(http_probe("https://api.github.com/user", auth))
    results.append(http_probe("https://api.github.com/rate_limit", auth))
    results.append(http_probe("https://api.github.com/user", auth_token))
    results.append(
        http_probe(
            "https://api.github.com/graphql",
            {**auth, "Content-Type": "application/json"},
            method="POST",
            data=b'{"query":"{ viewer { login } }"}',
        )
    )

    # npm packages (metadata GET only)
    results.append(
        http_probe(
            "https://npm.pkg.github.com/@gn00295120%2fdoes-not-exist-oidc-probe",
            {**auth, "Accept": "application/vnd.npm.install-v1+json"},
        )
    )
    results.append(
        http_probe(
            "https://npm.pkg.github.com/@gn00295120%2fdoes-not-exist-oidc-probe",
            auth_token,
        )
    )

    # GHCR token exchange (anonymous-style; with Bearer OIDC)
    results.append(
        http_probe(
            "https://ghcr.io/token?service=ghcr.io&scope=repository:gn00295120/does-not-exist:pull",
            auth,
        )
    )
    results.append(
        http_probe(
            "https://ghcr.io/v2/",
            auth,
        )
    )

    # Maven package HEAD/GET metadata
    results.append(
        http_probe(
            "https://maven.pkg.github.com/gn00295120/does-not-exist/com/example/oidc/1.0/oidc-1.0.pom",
            auth,
        )
    )

    # uploads
    results.append(http_probe("https://uploads.github.com/", auth))

    # codeload
    results.append(http_probe("https://codeload.github.com/gn00295120/oidc-claim-probe/legacy.tar.gz/refs/heads/main", auth))

    # Compare: unauthenticated baseline for rate_limit (should work without auth)
    results.append(http_probe("https://api.github.com/rate_limit", {"Accept": "application/json", "User-Agent": "oidc-rp-probe-h1"}))

    return results


def main() -> int:
    claims_only = "--claims-only" in sys.argv
    audience = os.environ.get("AUD") or "https://example.com/default"
    probe_name = os.environ.get("PROBE_NAME") or "unnamed"

    jwt, mint_meta = mint_oidc(audience)
    result: dict[str, Any] = {
        "probe_name": probe_name,
        "audience_requested": audience,
        "mint": mint_meta,
        "claims": None,
        "claim_keys": None,
        "environment_claim": None,
        "rp_probes": None,
    }

    if jwt:
        try:
            claims = decode_claims(jwt)
            # Drop nothing sensitive beyond standard claims; JWT itself not stored
            result["claims"] = claims
            result["claim_keys"] = sorted(claims.keys())
            result["environment_claim"] = claims.get("environment")
            result["sub"] = claims.get("sub")
            result["aud"] = claims.get("aud")
            result["repository"] = claims.get("repository")
            result["job_workflow_ref"] = claims.get("job_workflow_ref")
            result["ref_protected"] = claims.get("ref_protected")
        except Exception as e:
            result["mint"]["decode_error"] = str(e)[:200]
            jwt = None

    if jwt and not claims_only:
        result["rp_probes"] = probe_with_token(jwt, audience)

    # Explicitly ensure JWT not in result
    assert "jwt" not in result and "value" not in result

    out = "rp-result.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(json.dumps({k: result[k] for k in result if k != "claims"}, indent=2))
    if result.get("claims"):
        print("CLAIMS_SUMMARY", json.dumps({
            "aud": result.get("aud"),
            "sub": result.get("sub"),
            "environment": result.get("environment_claim"),
            "repository": result.get("repository"),
            "ref_protected": result.get("ref_protected"),
            "job_workflow_ref": result.get("job_workflow_ref"),
            "event_name": result["claims"].get("event_name"),
            "runner_environment": result["claims"].get("runner_environment"),
        }))
    if result.get("rp_probes"):
        for p in result["rp_probes"]:
            print(f"RP {p.get('status')} {p.get('method')} {p.get('url')} snip={str(p.get('body_snip') or p.get('error'))[:120]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
