"""
Web technology fingerprinting via HTTP headers and content analysis.
Pure Python, no external binaries.
"""

import re
from typing import Dict, List


CMS_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Joomla": [r"joomla", r"/components/com_"],
    "Drupal": [r"drupal", r"sites/default/files"],
    "Shopify": [r"shopify", r"cdn.shopify.com"],
    "Wix": [r"wix\.com", r"wixstatic\.com"],
    "Squarespace": [r"squarespace"],
    "Webflow": [r"webflow"],
    "Ghost": [r"ghost\.io", r'"ghost"'],
    "Magento": [r"magento", r"mage/"],
}

JS_PATTERNS = {
    "React": [r"react", r"_reactRoot", r"__NEXT_DATA__"],
    "Vue.js": [r"vue\.js", r"v-bind", r"nuxt"],
    "Angular": [r"angular", r"ng-app"],
    "jQuery": [r"jquery", r"\$\(document\)"],
    "Bootstrap": [r"bootstrap\.css", r"bootstrap\.js"],
    "Tailwind": [r"tailwindcss", r"tailwind\.css"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Gatsby": [r"gatsby", r"___gatsby"],
}

CDN_PATTERNS = {
    "Cloudflare": ["cf-ray", "cloudflare"],
    "Akamai": ["akamai"],
    "Fastly": ["fastly"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf"],
    "Vercel": ["vercel", "x-vercel"],
    "Netlify": ["netlify"],
}


async def detect_technologies(url: str) -> Dict:
    """Detect web technologies from HTTP response headers and content."""
    import httpx

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    result = {
        "web_server": None,
        "cms": None,
        "programming_languages": [],
        "javascript_frameworks": [],
        "cdn": [],
        "analytics": [],
        "technologies": [],
        "headers": {},
        "http_status": None,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=True) as client:
            response = await client.get(url)
            result["http_status"] = response.status_code
            result["headers"] = dict(response.headers)
            headers = response.headers
            content = response.text.lower()

            # Server header
            server = headers.get("server", "")
            if server:
                result["web_server"] = server
                result["technologies"].append(server)

            # X-Powered-By
            powered = headers.get("x-powered-by", "")
            if powered:
                result["technologies"].append(powered)
                if "php" in powered.lower():
                    result["programming_languages"].append("PHP")
                elif "asp" in powered.lower():
                    result["programming_languages"].append("ASP.NET")

            # Cookies
            cookies = headers.get("set-cookie", "")
            if "phpsessid" in cookies.lower():
                result["programming_languages"].append("PHP")
            if "asp.net" in cookies.lower():
                result["programming_languages"].append("ASP.NET")
            if "jsessionid" in cookies.lower():
                result["programming_languages"].append("Java")

            # CMS detection
            for cms_name, patterns in CMS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result["cms"] = cms_name
                        result["technologies"].append(f"CMS:{cms_name}")
                        break
                if result["cms"]:
                    break

            # JS frameworks
            for framework, patterns in JS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result["javascript_frameworks"].append(framework)
                        result["technologies"].append(f"JS:{framework}")
                        break

            # CDN/WAF
            hstr = str(dict(headers)).lower()
            for cdn, patterns in CDN_PATTERNS.items():
                for pattern in patterns:
                    if pattern in hstr or pattern in content:
                        result["cdn"].append(cdn)
                        result["technologies"].append(f"CDN:{cdn}")
                        break

            # Analytics
            if "google-analytics" in content or "gtag" in content or "ga.js" in content:
                result["analytics"].append("Google Analytics")
                result["technologies"].append("Analytics:Google Analytics")
            if "facebook.com/tr" in content or "fbevents" in content:
                result["analytics"].append("Facebook Pixel")
                result["technologies"].append("Analytics:Facebook Pixel")

    except Exception as e:
        result["error"] = str(e)

    return result
