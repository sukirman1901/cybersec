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
        "input": phone_number,
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
    }

    if not phone_number:
        result["error"] = "phone_number is required."
        return result

    if not _HAS_PHONENUMBERS:
        result["error"] = (
            "phonenumbers library not installed. Run: pip install phonenumbers"
        )
        return result

    try:
        parsed = phonenumbers.parse(phone_number, default_region or None)
    except NumberParseException as exc:
        result["error"] = f"Failed to parse phone number: {exc.error_type} — {exc._msg}"
        return result
    except Exception as exc:
        result["error"] = f"Failed to parse phone number: {exc}"
        return result

    result["valid"] = phonenumbers.is_valid_number(parsed)
    result["international_format"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    result["national_format"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.NATIONAL
    )
    result["country_code"] = parsed.country_code
    result["national_number"] = parsed.national_number

    # Region / country
    region_desc = ph_geocoder.description_for_number(parsed, "en")
    result["country"] = region_desc or ""
    regions = ph_geocoder.region_code_for_number(parsed)
    result["region"] = regions if regions else ""

    # Carrier
    carrier_name = ph_carrier.name_for_number(parsed, "en")
    result["carrier"] = carrier_name or "unknown"

    # Line type
    number_type = ph_carrier.number_type(parsed)
    _LINE_TYPES = {
        0: "UNKNOWN",
        1: "FIXED_LINE",
        2: "MOBILE",
        3: "FIXED_LINE_OR_MOBILE",
        4: "TOLL_FREE",
        5: "PREMIUM_RATE",
        6: "SHARED_COST",
        7: "VOIP",
        8: "PERSONAL_NUMBER",
        9: "PAGER",
        10: "UAN",
        11: "VOICEMAIL",
        12: "UNKNOWN",
    }
    result["line_type"] = _LINE_TYPES.get(int(number_type), str(number_type))

    # Timezones
    tz_list = ph_timezone.time_zones_for_number(parsed)
    result["timezones"] = list(tz_list) if tz_list else []

    # Generate lookup URLs
    intl_raw = result["international_format"].replace(" ", "").replace("+", "")
    e164 = result["international_format"].replace(" ", "")
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
            "url": f"https://www.google.com/search?q=%22{quote(e164)}%22",
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

    return result
