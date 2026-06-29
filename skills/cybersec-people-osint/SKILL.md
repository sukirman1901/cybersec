---
name: cybersec-people-osint
description: Use when user asks to track a person by phone number, Telegram username, email, or social media username — people investigation and identity tracing
---

## People OSINT Methodology

### Checklist

Create a todo list from the checklist below, then execute all steps immediately. Don't ask for confirmation — just run the tools and mark items complete as you go.

1. **Phone Lookup** — Call `phone_osint(phone_number)` to parse number, get region, carrier type, and generate lookup URLs (Truecaller, GetContact, sync.me)
2. **Telegram OSINT** — Call `telegram_osint(username)` to get Telegram user ID, bio, profile photo URL, and username history links
3. **Social Media Cross-Reference** — Call `social_osint(username)` to check the same username across 100+ social platforms (Instagram, Twitter, TikTok, Facebook, GitHub, Reddit, etc.)
4. **Email Investigation** — Call `email_osint(email)` to validate format, check MX records, domain reputation, and generate breach lookup URLs
5. **Cross-Reference Results** — Match findings across tools: same username on multiple platforms? Phone region matches Telegram bio location?
6. **Compile Identity Profile** — Aggregate: name, aliases, locations, social accounts, phone carrier, email breaches, Telegram activity

### Investigation Flow

```
Target: phone number or @username or email

phone_osint("08xxx") → carrier, region, lookup links
        ↓
telegram_osint("@user") → user ID, bio, photo, history
        ↓
social_osint("username") → found on Instagram, Twitter, TikTok, GitHub...
        ↓
email_osint("email@x.com") → domain info, breach history
        ↓
Cross-reference: same username everywhere? Same location in bio?
        ↓
Identity profile: name, location, social accounts, phone info
```

### Tools Available
`phone_osint`, `telegram_osint`, `social_osint`, `email_osint`, `people_osint`

### Output
Identity profile: real name (if found), aliases, location, phone carrier/region, social media accounts, email breach history, Telegram user details, and cross-referenced findings.

### Next Skill
Load `cybersec-report` to generate investigation report, or `cybersec-crisis` if this is an active fraud/scam case.
