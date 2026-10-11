# Supported Entity Types

[Back to README](../README.md)

This is an implementation inventory, not a claim that every value of each type
will be detected. Scores, context, thresholds, normalization, and optional
features all affect results. The release-gated synthetic subset and its limits
are documented in [Quality and claim policy](quality.md).

## Common

| Entity | Description | Score |
|--------|-------------|-------|
| `EMAIL_ADDRESS` | Email addresses | 0.9 |
| `URL` | HTTP/HTTPS URLs | 0.9 |
| `IP_ADDRESS` | IPv4 and IPv6 addresses (full, collapsed, link-local, loopback, IPv4-mapped) | 0.9 |
| `PHONE_NUMBER` | International phone numbers — E.164 format with separators, parenthesized area codes (context-aware) | 0.6 |
| `PHONE_EXTENSION` | Phone extensions (poste, ext, extension + 3-5 digits) | 0.85 |
| `IBAN_CODE` | Generic IBANs with mod-97 checksum validation and required context; complete compact UK IBANs also match without context | 0.7 |
| `CREDIT_CARD` | 16-digit card numbers (Luhn validated, context-aware) | 0.7 |
| `UUID` | Standard UUIDs | 0.95 |
| `MAC_ADDRESS` | MAC addresses — colon, hyphen, and Cisco dot formats (broadcast/null rejected) | 0.85 |
| `DATE_TIME` | ISO 8601, EU dd/mm/yyyy (context-aware), written French/English dates | 0.5 - 0.8 |
| `CRYPTO` | Bitcoin and Ethereum addresses | 0.9 |

## French

| Entity | Description | Score |
|--------|-------------|-------|
| `FR_PHONE_NUMBER` | French phone numbers — intl, national, compact (+33, 06, 0612345678) | 0.6 - 0.9 |
| `FR_IBAN` | French IBANs — spaced and compact (FR76...) | 0.9 - 0.95 |
| `FR_SSN` | Social security numbers (NIR) — spaced and compact, Corsica support | 0.8 - 0.85 |
| `FR_PASSPORT` | French passport numbers (context-aware) | 0.7 |
| `FR_ADDRESS` | Bounded French street + metropolitan postcode + city shape | 0.85 - 1.0 |

`FR_ADDRESS` requires a house number, a supported full street type (such as
`rue`, `avenue`, or `boulevard`), a street name, a five-digit postcode with a
metropolitan prefix from 01 through 95, and a city on the same line. It accepts
hyphenated cities and the prefixes `Le`, `La`, `Les`, `Saint`, and `Sainte`.
It does not validate a postal database. Abbreviated street types, overseas
postcodes, multiline addresses, and arbitrary multiword city names are outside
this rule's coverage; an unhyphenated multiword city may be only partly detected.
Ordinary text that happens to fit the full compound shape can also be detected.
Review the complete prepared address before sharing it.

## Aviation

| Entity | Description | Score |
|--------|-------------|-------|
| `AIRCRAFT_REGISTRATION` | French (F-XXXX), European, US N-numbers (context-aware) | 0.85 - 0.95 |
| `FLIGHT_NUMBER` | Amelia codes (IZM, RLA, AME, GJT, AF), IATA/ICAO (context-aware) | 0.4 - 0.9 |
| `CREW_CODE` | 3-letter crew codes (context-aware, with blocklist) | 0.85 |

## Authentication credentials

| Entity | Description | Score |
|--------|-------------|-------|
| `AUTH_TOKEN` | JWT-shaped tokens and validated HTTP Basic credentials | 0.95 |

Basic detection requires the case-insensitive `Basic` scheme, spaces or tabs,
and a complete standard-Base64 credential (padded or unpadded). Decoded bytes
must contain a username/password colon separator and no ASCII control bytes.
Empty components and non-ASCII credential bytes are supported. Only the encoded
credential is replaced; the scheme, header name, and surrounding syntax remain.
Restoration returns the exact encoded source spelling, including supported
URL-encoded or Unicode-escaped representations.

The recognizer does not scan arbitrary Base64 strings. Invalid padding,
non-canonical trailing bits, invalid suffixes, line breaks between the scheme
and credential, and split credentials are outside this recognizer's coverage.

## NER Entities

| Entity | Backend | Score | Feature flag |
|--------|---------|-------|--------------|
| `PERSON` | ML — DistilBERT multilingual NER (ONNX, INT8) | 0.6 - 1.0 | `ner` |
| `PERSON` | Heuristic — titles, self-introductions, and name dictionary | 0.55 - 0.80 | `ner-lite` |
| `LOCATION` | ML — DistilBERT multilingual NER (ONNX, INT8) | 0.6 - 1.0 | `ner` |

Enabled with `--ner`. See [NER setup](ner.md).

## Format Handling

Format is auto-detected by default (`--format auto`):

- **JSON** — Detected when content starts with `{` or `[` and parses as valid JSON. Recursively processes string values while leaving keys and non-string values unchanged. Output is reserialized, so insignificant whitespace and object-key order may change.
- **SQL** — Detected when the first word is a SQL keyword (SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP). Only supported quoted, PostgreSQL E-string, and dollar-quoted literal bodies are anonymized; syntax and spelling outside those spans are copied from the source.
- **CSV** — Parsed as a complete document so quoted commas, multiline fields, CRLF line endings, and escaped quotes keep their source representation outside anonymized field spans.
- **Text** — Default fallback. Applies regex patterns across the full text.

Force a format with `--format json`, `--format text`, `--format sql`, or `--format csv`.

## Context-Aware Detection

Context keywords work in two modes:

**Required** — Pattern only matches when a keyword appears within 80 characters:

| Entity | Context keywords |
|--------|-----------------|
| `CREW_CODE` | crew, pilot, equipage, captain, roster, planning, duty... |
| `FR_PASSPORT` | passeport, passport, document, identite |
| `FLIGHT_NUMBER` (IATA/ICAO) | flight, vol, departure, arrival, schedule, rotation |
| `AIRCRAFT_REGISTRATION` (US) | aircraft, avion, registration, immat, immatriculation, tail |
| `PHONE_NUMBER` | telephone, tel, phone, mobile, contact, call, number, whatsapp, sms, cell, fax |
| `IBAN_CODE` (generic rule) | iban, compte, account, virement, bank, banque, bancaire, transfer, swift, bic, payment, paiement |
| `DATE_TIME` (EU format) | date, naissance, birth, born, dob, expir, valid, depart, arrive, issued, delivre |
| `CREDIT_CARD` | card, carte, credit, debit, payment, paiement, cb |

The separate compact UK IBAN rule needs no context keyword or score boost.
It requires the complete GB field structure and mod-97 checksum; see the
[scope and release limits](quality.md#default-feature-corpus-v1).

**Score boost** — Pattern always matches, but confidence gets +0.15 when keywords are nearby:

| Entity | Context keywords |
|--------|-----------------|
| `FR_PHONE_NUMBER` | telephone, tel, phone, mobile, contact, appeler, numero, portable |
| `FR_IBAN` | iban, compte, account, virement, bank, banque, bancaire |
| `FR_SSN` | secu, securite sociale, ssn, nir, carte vitale, numero, immatriculation |
| `FR_ADDRESS` | adresse, address, domicile, habite, livraison, delivery |

Crew codes also use a blocklist to avoid matching common 3-letter words (THE, AND, FOR, VOL, PAX, ETA, UTC, AOG, etc.).
