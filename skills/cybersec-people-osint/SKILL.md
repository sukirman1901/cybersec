---
name: cybersec-people-osint
description: Use when user asks to track a person by phone number, Telegram username, email, or social media username — people investigation and identity tracing
---

## People OSINT Methodology

### Checklist

Select relevant branches for the supplied phone/username/email, not a mandatory
identity-enrichment chain. Public intelligence needs no engagement; before active
target probes require `engagement_gate` `init` + `authorize`, and confirmed `extend`
only for additional user-approved resources. Discovery grants no authority. Record
coverage/source dates and redact personal data not needed for the legitimate task.
Do not infer identity or exact location from username matches/carrier regions alone,
access private accounts, or treat generated lookup links as retrieved evidence.
Stop when the requested lookup is answered; do not automatically build a dossier.

Choose only a requested branch with the corresponding supplied input; these are
alternatives, not sequential steps:

- **Phone (optional)** — `phone_osint(phone_number)` for requested number-format/region/carrier metadata or generated lookup links. A numbering region is not a person's current location
- **Telegram (optional)** — `telegram_osint(username)` only for a supplied Telegram handle and requested public profile fields. Report only fields actually retrieved; history/search links are not retrieved history
- **Social (optional)** — `social_osint(username)` only for requested platform/username checks. A profile URL, HTTP response or matching handle is a candidate match, not proof of the same person
- **Email (optional)** — `email_osint(email)` for requested format/domain/MX metadata and generated search links. A breach-search URL is not a retrieved breach record or evidence that the address was breached
- **Cross-reference (optional)** — Only when explicitly requested and supported by relevant retrieved sources; preserve competing matches and uncertainty, not inferred real names or locations

### Investigation Flow

Route by supplied input and requested outcome; each branch is OPTIONAL:

| Supplied input | Run only when requested | Stop after |
|---|---|---|
| Phone number | `phone_osint` metadata/lookup-link branch | Requested metadata or labeled links |
| Telegram handle | `telegram_osint` public-profile branch | Requested actually retrieved fields |
| Social username | `social_osint` platform-check branch | Requested candidate matches and evidence |
| Email address | `email_osint` format/domain/search-link branch | Requested metadata or labeled unvisited links |

Do not derive new identifiers and fan out into the other branches. If a requested
branch lacks its input, record it as skipped; do not fill the gap by identifying a
person. An explicit multi-input request may select multiple independent branches,
but does not authorize an identity dossier or private-data enrichment.

### Tools Available
`phone_osint`, `telegram_osint`, `social_osint`, `email_osint`, `people_osint`

### Output
Return the minimum requested retrieved evidence with source, retrieval date and
coverage/limitations. Keep candidate matches distinct from established facts and
unvisited search links distinct from retrieved content. Generated breach-search
links are not breach retrieval; do not report a breach without an actually
retrieved, attributable record supporting that claim. No dossier: do not require
or collect real name, location, accounts or breach records to complete a simple
metadata/profile lookup. Omit and redact personal details unnecessary to the task.

### Next Skill
Load `cybersec-report` to generate investigation report, or `cybersec-crisis` if this is an active fraud/scam case.
