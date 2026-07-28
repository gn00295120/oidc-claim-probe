#!/usr/bin/env python3
import base64, json, os, sys, urllib.parse, urllib.request

aud = open("probe-aud.txt").read().splitlines()[0].strip() if os.path.exists("probe-aud.txt") else os.environ.get("AUD", "sts.amazonaws.com")
print("Audience=", aud)
url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
token = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
if "audience=" not in url:
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}audience={urllib.parse.quote(aud, safe='')}"
else:
    # replace or append
    url = url + ("&" if "?" in url else "?") + "audience=" + urllib.parse.quote(aud, safe="")

req = urllib.request.Request(url, headers={"Authorization": f"bearer {token}"})
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode()
        http = resp.status
except Exception as e:
    print("request failed", e)
    open("oidc-claims.json","w").write(json.dumps({"error": str(e), "audience_requested": aud}))
    sys.exit(0)

print("HTTP=", http)
print(body[:400])
try:
    d = json.loads(body)
except Exception as e:
    open("oidc-claims.json","w").write(json.dumps({"error":"non-json","body":body[:500],"audience_requested":aud}))
    sys.exit(0)

jwt = d.get("value") or d.get("token") or ""
if not jwt:
    open("oidc-claims.json","w").write(json.dumps({"error":"no-jwt","body":d,"audience_requested":aud}, default=str))
    print("no jwt", list(d.keys()))
    sys.exit(0)

parts = jwt.split(".")
pad = "=" * ((4 - len(parts[1]) % 4) % 4)
payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
print(json.dumps(payload, indent=2, sort_keys=True))
out = {
    "audience_requested": aud,
    "claims": payload,
    "claim_keys": sorted(payload.keys()),
}
open("oidc-claims.json","w").write(json.dumps(out, indent=2))
for k in ("sub","repository","job_workflow_ref","aud","iss","actor","workflow_ref","ref","event_name"):
    print(f"{k}=", payload.get(k))
