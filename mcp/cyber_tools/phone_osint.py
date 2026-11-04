"""
Phone OSINT — phone number intelligence and lookup URL generation.

Uses the `phonenumbers` library for offline parsing (carrier, region, line type).
Generates lookup URLs for Truecaller, GetContact, sync.me, and other services.
No paid APIs required.
"""

from typing import Any
from urllib.parse import quote

try:
    import phonenumbers
    from phonenumbers import carrier as ph_carrier
    from phonenumbers import geocoder as ph_geocoder
    from phonenumbers import timezone as ph_timezone
    from phonenumbers.phonenumberutil import NumberParseException
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False


def phone_osint(phone_number: str, default_region: str = "") -> dict:
    """Gather intelligence about a phone number.

    Parses the number offline using the phonenumbers library to extract
    carrier, region, line type, and timezones. Generates lookup URLs for
    caller ID and spam-check services.

    Args:
        phone_number:  Phone number in international or local format.
        default_region: ISO 3166-1 alpha-2 region code for local numbers
                        (e.g., "ID" for Indonesia, "US" for USA).

    Returns:
        A dict with parsed number info, carrier, region, line type,
        lookup URLs, and error.
    """
    result: dict[str, Any] = {
        "input": "[REDACTED]",
        "valid": False,
        "international_format": "",
        "national_format": "",
        "country_code": None,
        "national_number": None,
        "country": "",
        "region": "",
        "carrier": "",
        "line_type": "",
        "timezones": [],
        "lookup_urls": [],
        "error": None,
        "coverage_complete": False,
        "assessment": "numbering_plan_metadata_only",
        "identity_verified": False,
        "external_requests": 0,
        "coverage": "Offline numbering-plan metadata; not identity, reachability, current carrier or physical-location verification. Lookup links are untested templates; normalized input number remains in results.",
    }

    if not isinstance(phone_number, str) or not phone_number.strip() or len(phone_number) > 128:
        result["error"] = "phone_number must be a nonempty string of at most 128 characters."
        return result
    if not isinstance(default_region, str) or (default_region and (len(default_region) != 2 or not default_region.isalpha())):
        result['error'] = 'default_region must be a two-letter region code.'
        return result

    if not _HAS_PHONENUMBERS:
        result["error"] = (
            "phonenumbers library not installed. Run: pip install phonenumbers"
        )
        return result

    try:
        parsed = phonenumbers.parse(phone_number, default_region.upper() or None)
    except NumberParseException as exc:
        result["error"] = f"Failed to parse phone number (code {exc.error_type})."
        return result
    except Exception as exc:
        result["error"] = "Phone-number parser unavailable or input unsupported."
        return result

    try:
        result["valid"] = phonenumbers.is_valid_number(parsed)
        if not result['valid']:
            result.update(coverage_complete=True, error='Number does not match a valid numbering-plan allocation.')
            return result
        result.update(
            international_format=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            national_format=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            country_code=parsed.country_code, national_number=parsed.national_number,
            country=ph_geocoder.country_name_for_number(parsed, 'en') or '',
            region=phonenumbers.region_code_for_number(parsed) or '',
            carrier=ph_carrier.name_for_number(parsed, 'en') or 'unknown',
            line_type=phonenumbers.PhoneNumberType.to_string(phonenumbers.number_type(parsed)),
            timezones=list(ph_timezone.time_zones_for_number(parsed)),
        )
        canonical = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        result['error'] = 'Numbering-plan metadata unavailable or unsupported.'
        return result

    # Templates only: no lookup service is contacted or verified.
    intl_raw = canonical.removeprefix('+')
    e164 = quote(canonical, safe='')
    result["lookup_urls"] = [
        {
            "service": "Truecaller",
            "url": f"https://www.truecaller.com/search/{intl_raw}",
            "description": "Caller ID and spam detection",
        },
        {
            "service": "GetContact",
            "url": f"https://www.getcontact.com/search/{e164}",
            "description": "Caller ID and tag lookup",
        },
        {
            "service": "Sync.me",
            "url": f"https://sync.me/search/?number={e164}",
            "description": "Phone number lookup and reviews",
        },
        {
            "service": "NumLookup",
            "url": f"https://www.numlookup.com/{intl_raw}",
            "description": "Reverse phone lookup",
        },
        {
            "service": "WhoCallsMe",
            "url": f"https://whocallsme.com/Phone-Number.aspx/{e164}",
            "description": "Spam and scam report database",
        },
        {
            "service": "Google Search",
            "url": f"https://www.google.com/search?q=%22{e164}%22",
            "description": "Search for this number on Google",
        },
        {
            "service": "Google Search (no country code)",
            "url": f"https://www.google.com/search?q=%22{quote(str(result['national_number']))}%22",
            "description": "Search national number format",
        },
        {
            "service": "Whoscall",
            "url": f"https://www.whoscall.com/en/search?number={e164}",
            "description": "Caller ID database",
        },
        {
            "service": "Eyecon",
            "url": f"https://www.eyecon.com/{e164}",
            "description": "Caller ID with photo",
        },
        {
            "service": "CallerID Test",
            "url": f"https://calleridtest.com/{e164}",
            "description": "Caller ID verification",
        },
    ]

    result['coverage_complete'] = True
    return result
