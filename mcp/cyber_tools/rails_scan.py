"""Scan Ruby on Rails app — exposed configs, mass assignment, debug console, routes."""

import httpx

RAILS_PATHS = [
    "/assets/",
    "/rails/info",
    "/rails/info/routes",
    "/rails/info/properties",
    "/rails/mailers",
    "/rails/db",
    "/sidekiq",
    "/delayed_job",
    "/admin",
    "/admin/login",
    "/administrator",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/credentials.yml.enc",
    "/.env",
    "/Gemfile",
    "/Gemfile.lock",
    "/db/schema.rb",
    "/db/structure.sql",
    "/log/development.log",
    "/log/production.log",
    "/tmp/",
    "/public/uploads/",
]


async def rails_scan(target: str) -> dict:
    """Scan a Ruby on Rails application for common security misconfigurations."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    findings = []
    base = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.get(base)
        headers = dict(resp.headers)

        # Check Rails-specific headers
        x_powered = headers.get("x-powered-by", "")
        if "rails" in x_powered.lower():
            findings.append({
                "type": "rails_disclosure",
                "header": "x-powered-by",
                "value": x_powered,
                "risk": "MEDIUM",
            })

        # Check for Rails session cookie
        for cookie_name, cookie_value in resp.cookies.items():
            if "_session" in cookie_name.lower() or "rack.session" in cookie_name.lower():
                findings.append({
                    "type": "rails_session",
                    "cookie": cookie_name,
                    "note": "Rails session cookie detected",
                    "risk": "INFO",
                })

        # Check common Rails paths
        for p in RAILS_PATHS:
            try:
                pr = await client.get(base + p)
                if pr.status_code == 200:
                    content = pr.text.lower()
                    sensitivity = (
                        "HIGH"
                        if any(
                            kw in content
                            for kw in ["password", "secret", "credentials", "encrypted"]
                        )
                        else "MEDIUM"
                    )
                    findings.append({
                        "type": "exposed_path",
                        "path": p,
                        "status": pr.status_code,
                        "size": len(pr.text),
                        "risk": sensitivity,
                    })
                elif pr.status_code == 302:
                    findings.append({
                        "type": "redirect_to_login",
                        "path": p,
                        "redirect": str(pr.headers.get("location", "")),
                        "risk": "INFO",
                    })
            except Exception:
                continue

        # Check mass assignment / strong params
        try:
            mr = await client.post(
                base + "/api/users",
                json={"user": {"admin": True, "role": "admin"}},
                headers={"Content-Type": "application/json"},
            )
            if mr.status_code in [200, 201, 302]:
                findings.append({
                    "type": "mass_assignment",
                    "note": "POST to /api/users with admin params succeeded",
                    "risk": "CRITICAL",
                })
        except Exception:
            pass

        # Check debug/console
        try:
            cr = await client.get(base + "/rails/console")
            if cr.status_code == 200:
                findings.append({
                    "type": "rails_console",
                    "note": "Rails console may be exposed",
                    "risk": "CRITICAL",
                })
        except Exception:
            pass

    return {
        "target": target,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "framework": "Ruby on Rails",
    }
