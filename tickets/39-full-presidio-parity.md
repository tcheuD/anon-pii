# Ticket #39: Full Presidio Feature Parity

**Priority:** High
**Status:** Planning
**Goal:** Every capability Presidio offers must have a Rust equivalent — no exceptions.

---

## 1. Entity Type Parity

Presidio ships ~50 built-in entity types. Below is the exhaustive 1:1 map.

### 1A. Global Entities

| Presidio Entity | Rust Status | What's Missing | Complexity |
|----------------|-------------|----------------|------------|
| `EMAIL_ADDRESS` | **Done** | — | — |
| `URL` | **Done** | — | — |
| `CREDIT_CARD` | **Done** | Rust already has Luhn + IIN/BIN prefix validation. Presidio equivalent. | — |
| `CRYPTO` | **Done** | Bitcoin + Ethereum patterns. Presidio also validates Base58/Bech32 checksums — we skip this (regex sufficient, false-positive risk low). | — |
| `IP_ADDRESS` | **Done** | ~~IPv4 only. Need IPv6.~~ (FIXED) IPv6 pattern added: full, collapsed, link-local, loopback, IPv4-mapped. | — |
| `PHONE_NUMBER` | **Done** | ~~French only. Need generic international format.~~ (FIXED) Generic `intl_phone` pattern added with context gating + `PHONE_EXTENSION`. | — |
| `IBAN_CODE` | **Done** | ~~French only. Need all-country IBAN with mod-97 checksum.~~ (FIXED) Generic IBAN pattern with mod-97 validation, context-gated. FR_IBAN kept separate. | — |
| `MAC_ADDRESS` | **Done** | ~~Colon, hyphen, and Cisco dot formats.~~ (FIXED) All 3 formats with broadcast/null rejection. | — |
| `DATE_TIME` | **Done** | ~~ISO 8601, French `dd/mm/yyyy`, written dates.~~ (FIXED) 4 patterns: ISO 8601, EU dd/mm/yyyy (context-gated), written French, written English. | — |
| `PERSON` | **Done** | ML NER (ONNX) + heuristic (INSEE dictionary) + sign-off + name consistency. Exceeds Presidio. | — |
| `LOCATION` | **Done** | ~~NLP-dependent. Requires NER model that outputs LOC labels.~~ (FIXED) ML NER passes B-LOC/I-LOC labels through as LOCATION entity. | — |
| `NRP` | **Skip** | Nationality/religion/political group. NLP-dependent, not enabled by default even in Presidio. Ethically questionable to detect. Defer indefinitely. | — |
| `MEDICAL_LICENSE` | **Missing** | US medical license number pattern + checksum. | Low |

### 1B. United States (8 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `US_SSN` | **Done** | Delimiter consistency, zero-group rejection, invalid prefix blocklist (000, 666, 9xx) | Low |
| `US_BANK_NUMBER` | **Done** | 8-17 digit pattern, context-gated | Low |
| `US_DRIVER_LICENSE` | **Done** | ~~State-specific patterns (50 states). Presidio uses ~15 regex groups.~~ (FIXED) 3 regex groups: letter+5-9 digits, letter+10-12 digits, 2 letters+5-7 digits. All context-gated. | Medium |
| `US_ITIN` | **Done** | ~~9 digits starting with 9, format `9XX-XX-XXXX`~~ (FIXED) Pattern + `valid_us_itin()` validator (group range check). | Low |
| `US_PASSPORT` | **Done** | 9-digit pattern, context-gated | Low |
| `US_MBI` | **Done** | ~~11-char Medicare Beneficiary ID, positional validation (excludes S,L,O,I,B,Z)~~ (FIXED) Positional regex with character class exclusions. | Low |
| `ABA_ROUTING` | **Done** | ~~9-digit routing number, weighted checksum `[3,7,1,3,7,1,3,7,1]` mod-10~~ (FIXED) `valid_aba_routing()` with prefix + weighted checksum validation. | Low |
| `MEDICAL_LICENSE` | **Done** | (Same as global — listed once) | Low |

### 1C. United Kingdom (2 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `UK_NHS` | **Done** | ~~10-digit number, mod-11 checksum~~ (FIXED) 2 patterns (spaced + compact), mod-11 validator, context-gated | Low |
| `UK_NINO` | **Done** | ~~National Insurance Number, prefix blocklist (BG, GB, NK, KN, NT, TN, ZZ)~~ (FIXED) Regex with char class prefix filtering + blocklist validator, context-gated | Low |

### 1D. Spain (2 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `ES_NIF` | **Done** | ~~Personal tax ID, pattern + checksum~~ (FIXED) Pattern + mod-23 validator, context-gated | Low |
| `ES_NIE` | **Done** | ~~Foreigner ID card, pattern + checksum~~ (FIXED) Pattern + mod-23 validator (X/Y/Z prefix), context-gated | Low |

### 1E. Italy (5 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `IT_FISCAL_CODE` | **Missing** | 16-char code, odd/even weighted checksum, mod-26 control char | Medium |
| `IT_DRIVER_LICENSE` | **Missing** | Pattern + context | Low |
| `IT_VAT_CODE` | **Missing** | Pattern + context | Low |
| `IT_PASSPORT` | **Missing** | Pattern + context | Low |
| `IT_IDENTITY_CARD` | **Missing** | Pattern + context | Low |

### 1F. India (6 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `IN_AADHAAR` | **Missing** | 12-digit, Verhoeff algorithm checksum, palindrome rejection | Medium |
| `IN_PAN` | **Missing** | 10-char alphanumeric format validation | Low |
| `IN_VEHICLE_REGISTRATION` | **Missing** | Pattern + context | Low |
| `IN_PASSPORT` | **Missing** | Pattern + context | Low |
| `IN_VOTER` | **Missing** | Pattern + context | Low |
| `IN_GSTIN` | **Missing** | 15-char, state code validation (01-37), embedded PAN | Medium |

### 1G. Australia (4 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `AU_ABN` | **Missing** | 11-digit, weighted checksum `[10,1,3,5,7,9,11,13,15,17,19]` mod-89 | Low |
| `AU_ACN` | **Missing** | 9-digit, checksum | Low |
| `AU_TFN` | **Missing** | 9-digit, weighted checksum `[1,4,3,7,5,8,6,9,10]` mod-11 | Low |
| `AU_MEDICARE` | **Missing** | Pattern + context | Low |

### 1H. South Korea (5 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `KR_RRN` | **Missing** | 13-digit resident registration, checksum | Low |
| `KR_BRN` | **Missing** | 10-digit business registration, weighted checksum | Low |
| `KR_DRIVER_LICENSE` | **Missing** | Pattern | Low |
| `KR_FRN` | **Missing** | Foreign registration number | Low |
| `KR_PASSPORT` | **Missing** | Pattern | Low |

### 1I. Singapore (2 entities)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `SG_NRIC_FIN` | **Missing** | First char S/T/F/G/M + 7 digits + check letter | Low |
| `SG_UEN` | **Missing** | Unique entity number, pattern + context | Low |

### 1J. Poland (1 entity)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `PL_PESEL` | **Missing** | 11-digit, weighted checksum `[1,3,7,9,1,3,7,9,1,3]` mod-10 | Low |

### 1K. Finland (1 entity)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `FI_PERSONAL_IDENTITY_CODE` | **Missing** | 11-char, date validation + mod-31 control character lookup | Medium |

### 1L. Thailand (1 entity)

| Presidio Entity | Rust Status | Validation Needed | Complexity |
|----------------|-------------|-------------------|------------|
| `TH_TNIN` | **Missing** | 13-digit Thai national ID | Low |

### Entity Tally

| Category | Presidio Count | Rust Done | Rust Partial | Rust Missing |
|----------|---------------|-----------|--------------|--------------|
| Global | 13 | 7 | 3 | 3 |
| US | 8 | 0 | 0 | 8 |
| UK | 2 | 0 | 0 | 2 |
| Spain | 2 | 0 | 0 | 2 |
| Italy | 5 | 0 | 0 | 5 |
| India | 6 | 0 | 0 | 6 |
| Australia | 4 | 0 | 0 | 4 |
| South Korea | 5 | 0 | 0 | 5 |
| Singapore | 2 | 0 | 0 | 2 |
| Poland | 1 | 0 | 0 | 1 |
| Finland | 1 | 0 | 0 | 1 |
| Thailand | 1 | 0 | 0 | 1 |
| **Total** | **50** | **7** | **3** | **40** |

Plus Rust has 6 entity types Presidio lacks: `UUID`, `AUTH_TOKEN`, `JOB_TITLE`, `EMPLOYEE_ID`, `PHONE_EXTENSION`, `CREW_CODE`.

---

## 2. Validation Parity

Presidio validates many entities with checksums beyond regex. Current Rust validation status:

| Validation | Presidio | Rust Status |
|-----------|----------|-------------|
| **Luhn** (credit cards) | Yes | **Done** |
| **IIN/BIN prefix** (credit cards) | No (Presidio doesn't do this) | **Done** (Rust ahead) |
| **mod-97** (IBAN) | Yes | **Done** — `iban_mod97()` validates all IBAN_CODE detections |
| **Country IBAN formats** (length + structure per country) | Yes (via `iban_patterns.py`) | **Partial** — regex enforces 2-letter country + 2 check digits + 11-30 BBAN. No per-country length table. |
| **IP parsing** (stdlib validation) | Yes (`ipaddress.ip_address()`) | **Done** — regex validates octets 0-255 for IPv4, IPv6 regex covers full/collapsed/link-local/loopback/mapped forms |
| **Phone parsing** (`python-phonenumbers`) | Yes | **Partial** — Regex-based with context gating. No stdlib-level validation but covers E.164 format with separators/area codes. |
| **Verhoeff** (IN_AADHAAR) | Yes | **Missing** |
| **mod-11** (UK_NHS, AU_TFN) | Yes | **Partial** — `valid_uk_nhs()` implemented for UK_NHS, AU_TFN still missing |
| **Weighted checksums** (ABA, AU_ABN, KR_BRN, PL_PESEL) | Yes | **Missing** |
| **IT fiscal code** (odd/even weighted, mod-26) | Yes | **Missing** |
| **FI identity code** (date + mod-31) | Yes | **Missing** |
| **Base58/Bech32 checksum** (crypto) | Yes | **Skip** — regex is sufficient, extremely low false-positive rate |

**Decision:** Implement checksum validation for every entity that Presidio validates. This is cheap in Rust and prevents false positives. Implement them as `fn validate_xxx(s: &str) -> bool` functions in `patterns.rs`, called from the detection pipeline (same pattern as existing `luhn_check` / `valid_card_prefix`).

---

## 3. Anonymization Operator Parity

Presidio has 8 anonymization operators. Rust currently has 1 (token replacement).

| Operator | Presidio | Rust Status | Complexity |
|----------|----------|-------------|------------|
| `replace` | Replace with `<ENTITY_TYPE>` or custom value | **Done** (as `[ENTITY_TYPE_hex]` tokens) | — |
| `redact` | Remove PII completely (empty string) | **Missing** | Trivial |
| `hash` | SHA-256/512/MD5 hash of PII | **Missing** | Low (use `sha2`/`md5` crates) |
| `mask` | Replace with repeated char (`****`) | **Missing** | Low |
| `encrypt` | AES-CBC encryption (reversible) | **Missing** | Medium (use `aes`/`cbc` crates) |
| `decrypt` | Reverse AES-CBC | **Missing** | Medium |
| `keep` | No-op (preserve original) | **Missing** | Trivial |
| `custom` | User-provided lambda | **Missing** | Medium (CLI: format string; library: closure) |

**Implementation plan:** Add an `--operator` CLI flag with values: `token` (default, current behavior), `redact`, `hash`, `mask`, `encrypt`, `keep`. The `custom` operator can be a `--replace-with` format string (e.g. `--replace-with '<{entity_type}>'`).

Add `--mask-char` (default `*`), `--mask-count` (default: match original length), `--hash-algo` (default: sha256), `--encrypt-key` (128/192/256-bit).

For `encrypt`/`decrypt`: the restore command already handles deanonymization via mapping. Encryption adds a second reversible path that doesn't require a mapping file. Useful for data pipelines.

---

## 4. Context Enhancement Parity

| Feature | Presidio | Rust Status |
|---------|----------|-------------|
| Keyword context matching | Yes | **Done** (dual mode: gate + boost) |
| Score boost magnitude | configurable (default 0.35) | **Done** (fixed 0.15) |
| Configurable boost factor | Yes (`context_similarity_factor`) | **Missing** — hardcoded at 0.15 |
| Minimum score with context | Yes (`min_score_with_context_similarity=0.4`) | **Missing** |
| Lemma-based matching | Yes (spaCy lemmatizer) | **Missing** — exact string match only |
| Outer context (column names/metadata) | Yes | **Partial** — column-header detection exists in `detection.rs` but not as general outer context API |
| Configurable context window | Yes | **Done** (80 chars, via `CONTEXT_WINDOW` constant) |

**Decision:** Lemma matching is overkill for regex patterns (our context keywords are already root forms). But we should:
1. Make `CONTEXT_SCORE_BOOST` configurable via CLI (`--context-boost`, default 0.15)
2. Add `--min-score-with-context` (default: keep current behavior)
3. The column-header outer context already covers the most important case

---

## 5. NLP Engine Parity

| Feature | Presidio | Rust Status |
|---------|----------|-------------|
| spaCy NER | Yes (default) | N/A (Python-only) |
| Stanza NER | Yes (alternative) | N/A (Python-only) |
| HuggingFace Transformers NER | Yes | **Done** — ONNX Runtime with distilbert-ner model |
| GLiNER (zero-shot NER) | Yes (community) | **Missing** — would need ONNX export of GLiNER model |
| Multi-model support | Yes (parallel models) | **Missing** — single model only |
| PERSON detection | Yes | **Done** — ML + heuristic + INSEE + sign-off + consistency pass |
| LOCATION detection | Yes (via NER) | **Missing** — ML model outputs LOC but we discard non-PER labels |
| NRP detection | Yes (via NER) | **Skip** — ethically questionable, not in scope |
| DATE_TIME via NER | Yes (via NER) | **Missing** — we could use DATE labels from NER model |

**Decision:** The biggest NER gap is `LOCATION`. Our ONNX model (distilbert-ner) already outputs `B-LOC`/`I-LOC` labels — we just filter them out in `ml.rs`. Enabling LOCATION detection requires:
1. Pass LOC labels through from `ml.rs`
2. Add a `LOCATION` entity type
3. Apply appropriate scoring/blocklist (high false-positive risk with short location names)

For GLiNER: interesting but not blocking. Can be a future enhancement.

---

## 6. Structured Data Parity

| Feature | Presidio | Rust Status |
|---------|----------|-------------|
| JSON recursive anonymization | Yes | **Done** — recursive `serde_json::Value` walk, key + value anonymization |
| CSV cell-by-cell processing | No (column-level only) | **Done** — RFC 4180, cell-by-cell (Rust ahead) |
| SQL string-literal parsing | No | **Done** — single-quoted literal extraction (Rust ahead) |
| Column-level entity detection strategy | Yes (most_common, highest_confidence, mixed) | **Missing** — Rust does cell-by-cell which is more granular |
| Pandas DataFrame support | Yes | N/A — no Rust equivalent needed (CLI tool, not library) |
| Faker integration (synthetic data) | Yes | **Missing** — useful for realistic replacement |

**Decision:** Column-level strategy is less precise than cell-by-cell (which Rust already does). No action needed. Faker-style synthetic replacement is a nice-to-have that ties into operator parity (custom operator with format templates).

---

## 7. Image Redaction Parity

| Feature | Presidio | Rust Status |
|---------|----------|-------------|
| Image PII detection (OCR + regex) | Yes (Tesseract/Azure OCR) | **Missing** |
| Image redaction (color fill) | Yes | **Missing** |
| DICOM medical image support | Yes | **Skip** — out of scope |
| PDF annotation | Yes | **Missing** |

**Decision:** Image redaction is a significant feature. Implementation path:
1. Use `leptess` or `tesseract-rs` crate for OCR
2. Use `image` crate for redaction (draw filled rectangles)
3. Add `anon image` subcommand
4. PDF support via `lopdf` or `pdf` crate

This is a Phase 3 feature — get entity + operator parity first.

---

## 8. API / Integration Parity

| Feature | Presidio | Rust Status |
|---------|----------|-------------|
| REST API (`/analyze`, `/anonymize`) | Yes | **Partial** — has anonymizing reverse proxy, not a general API |
| Supported entities endpoint | Yes (`/supportedentities`) | **Missing** as API (CLI has `list-entities`) |
| Ad-hoc recognizer API | Yes (per-request custom recognizers in JSON) | **Missing** |
| YAML no-code configuration | Yes (recognizer + engine config from YAML) | **Missing** |
| LiteLLM proxy integration | Yes (pre-call masking) | **Partial** — has Anthropic proxy, not generic LLM proxy |

**Decision:** The REST API is important for integration. Rust already has `axum` for the proxy — extending it with `/analyze` and `/anonymize` endpoints is straightforward. Ad-hoc recognizer API and YAML config are Phase 3.

---

## Implementation Roadmap

### Phase 1: Complete Global Entity Coverage (highest impact)

These are the entities every PII tool must detect, regardless of domain.

| # | Task | Entities Added | Complexity | Est. Patterns |
|---|------|---------------|------------|---------------|
| ~~1.1~~ | ~~Add IPv6 pattern~~ (FIXED) | `IP_ADDRESS` (complete) | Low | +1 |
| ~~1.2~~ | ~~Add generic international phone~~ (FIXED) | `PHONE_NUMBER` (complete) | Medium | +2 |
| ~~1.3~~ | ~~Add generic IBAN with mod-97 validation~~ (FIXED) | `IBAN_CODE` (complete) | Medium | +2 |
| ~~1.4~~ | ~~Add MAC address patterns~~ (FIXED) | `MAC_ADDRESS` (complete) | Low | +3 |
| ~~1.5~~ | ~~Add DATE_TIME with context gating~~ (FIXED) | `DATE_TIME` (complete) | High | +4 |
| ~~1.6~~ | ~~Enable LOCATION from existing NER model~~ (FIXED) | `LOCATION` (complete) | Medium | +0 |
| 1.7 | Add US_SSN | `US_SSN` (new) | Low | +2 |
| 1.8 | Add MEDICAL_LICENSE | `MEDICAL_LICENSE` (new) | Low | +1 |

**Result after Phase 1:** All 13 global entities covered + US_SSN.

### Phase 2: Country-Specific Entities (breadth)

Implement all country recognizers. Group by country, each is a self-contained PR.

| # | Task | Entities Added | Complexity |
|---|------|---------------|------------|
| ~~2.1~~ | ~~US entities (7 remaining)~~ (FIXED) | `US_BANK_NUMBER`, `US_DRIVER_LICENSE`, `US_ITIN`, `US_PASSPORT`, `US_MBI`, `ABA_ROUTING`, `MEDICAL_LICENSE` | Medium |
| ~~2.2~~ | ~~UK entities~~ (FIXED) | `UK_NHS`, `UK_NINO` | Low |
| ~~2.3~~ | ~~Spain entities~~ (FIXED) | `ES_NIF`, `ES_NIE` | Low |
| 2.4 | Italy entities | `IT_FISCAL_CODE`, `IT_DRIVER_LICENSE`, `IT_VAT_CODE`, `IT_PASSPORT`, `IT_IDENTITY_CARD` | Medium (fiscal code checksum) |
| 2.5 | India entities | `IN_AADHAAR`, `IN_PAN`, `IN_VEHICLE_REGISTRATION`, `IN_PASSPORT`, `IN_VOTER`, `IN_GSTIN` | Medium (Verhoeff algorithm) |
| 2.6 | Australia entities | `AU_ABN`, `AU_ACN`, `AU_TFN`, `AU_MEDICARE` | Low |
| 2.7 | South Korea entities | `KR_RRN`, `KR_BRN`, `KR_DRIVER_LICENSE`, `KR_FRN`, `KR_PASSPORT` | Low |
| 2.8 | Singapore entities | `SG_NRIC_FIN`, `SG_UEN` | Low |
| 2.9 | Poland entity | `PL_PESEL` | Low |
| 2.10 | Finland entity | `FI_PERSONAL_IDENTITY_CODE` | Medium (date + mod-31) |
| 2.11 | Thailand entity | `TH_TNIN` | Low |

**Result after Phase 2:** All ~50 Presidio entity types covered.

### Phase 3: Anonymization Operators (depth)

| # | Task | Complexity |
|---|------|------------|
| 3.1 | Add `--operator` flag with `redact`, `keep` modes | Low |
| 3.2 | Add `mask` operator with `--mask-char`, `--mask-count` | Low |
| 3.3 | Add `hash` operator with `--hash-algo` (sha256/sha512/md5) | Low |
| 3.4 | Add `encrypt` operator (AES-CBC) with `--encrypt-key` | Medium |
| 3.5 | Add `decrypt` to restore command | Medium |
| 3.6 | Add `--replace-with` format string for custom replacement | Low |

**Result after Phase 3:** Full operator parity.

### Phase 4: Advanced Features

| # | Task | Complexity |
|---|------|------------|
| 4.1 | REST API endpoints (`/analyze`, `/anonymize`, `/supportedentities`) | Medium |
| 4.2 | Configurable context boost via CLI | Low |
| 4.3 | Image redaction subcommand (OCR + redact) | High |
| 4.4 | PDF text extraction + redaction | High |
| 4.5 | YAML recognizer configuration (no-code custom patterns) | Medium |
| 4.6 | Generic LLM proxy (beyond Anthropic) | Medium |

---

## Architecture Decision: How to Organize 50+ Entity Types

With ~50 entity types and ~80+ patterns, the current flat `PATTERNS` array in `patterns.rs` becomes unwieldy. Proposed structure:

```
src/
├── patterns/
│   ├── mod.rs          # PiiPattern struct, PATTERNS aggregation, shared validators
│   ├── global.rs       # EMAIL, URL, IP, PHONE, IBAN, CREDIT_CARD, CRYPTO, MAC, DATE_TIME
│   ├── french.rs       # FR_PHONE, FR_IBAN, FR_SSN, FR_PASSPORT (existing)
│   ├── aviation.rs     # AIRCRAFT_REGISTRATION, FLIGHT_NUMBER, CREW_CODE, EMPLOYEE_ID
│   ├── us.rs           # US_SSN, US_BANK_NUMBER, US_DRIVER_LICENSE, US_ITIN, US_PASSPORT, US_MBI, ABA_ROUTING
│   ├── uk.rs           # UK_NHS, UK_NINO
│   ├── es.rs           # ES_NIF, ES_NIE
│   ├── it.rs           # IT_FISCAL_CODE, IT_DRIVER_LICENSE, IT_VAT_CODE, IT_PASSPORT, IT_IDENTITY_CARD
│   ├── in_.rs          # IN_AADHAAR, IN_PAN, IN_VEHICLE_REGISTRATION, IN_PASSPORT, IN_VOTER, IN_GSTIN
│   ├── au.rs           # AU_ABN, AU_ACN, AU_TFN, AU_MEDICARE
│   ├── kr.rs           # KR_RRN, KR_BRN, KR_DRIVER_LICENSE, KR_FRN, KR_PASSPORT
│   ├── sg.rs           # SG_NRIC_FIN, SG_UEN
│   ├── pl.rs           # PL_PESEL
│   ├── fi.rs           # FI_PERSONAL_IDENTITY_CODE
│   ├── th.rs           # TH_TNIN
│   └── validators.rs   # Luhn, mod-97, mod-11, Verhoeff, weighted checksums
```

Each country module exports a `&[PiiPattern]` slice. `mod.rs` concatenates them all into the master `PATTERNS` list. This keeps things maintainable without changing the detection engine.

---

## Validation Functions Needed

All implemented in `patterns/validators.rs`:

```rust
// Existing
fn luhn_check(number: &str) -> bool;
fn valid_card_prefix(number: &str) -> bool;

// New
fn iban_mod97(iban: &str) -> bool;              // IBAN mod-97 checksum
fn verhoeff_check(number: &str) -> bool;        // IN_AADHAAR
fn mod11_check(number: &str) -> bool;           // UK_NHS, AU_TFN
fn weighted_checksum(number: &str, weights: &[u32], modulus: u32) -> bool;  // ABA, AU_ABN, KR_BRN, PL_PESEL
fn it_fiscal_code_check(code: &str) -> bool;    // Italy fiscal code
fn fi_identity_check(code: &str) -> bool;       // Finland identity code
fn iban_country_format(iban: &str) -> bool;     // Per-country IBAN length + structure
```

---

## CLI Flag Changes

```
# Phase 1 (no breaking changes)
--ner                   # existing — enable NER-based PERSON + LOCATION detection

# Phase 3
--operator <MODE>       # token (default) | redact | hash | mask | encrypt | keep
--mask-char <CHAR>      # default: '*'
--mask-from-end         # mask from end instead of start
--hash-algo <ALGO>      # sha256 (default) | sha512 | md5
--encrypt-key <KEY>     # AES key (128/192/256-bit, hex-encoded)
--replace-with <FMT>    # format string, e.g. '<{entity_type}>' or 'REDACTED'
--context-boost <F>     # context score boost factor (default: 0.15)
```

---

## What We Explicitly Skip (and Why)

| Presidio Feature | Reason to Skip |
|-----------------|----------------|
| `NRP` entity (nationality/religion/political) | Ethically questionable to classify. Not a PII type. Not enabled by default in Presidio either. |
| Pandas DataFrame support | Python-only concept. Rust CLI processes files/stdin — more universal. |
| Spark/Databricks integration | Big data infrastructure. Irrelevant for a CLI tool — Rust is already fast enough to process millions of lines. |
| Azure AI Language (cloud NER) | Vendor lock-in. Rust ML NER achieves comparable results locally. |
| Azure Health Data Services | Healthcare-specific cloud service. Out of scope. |
| LLM-based extraction (LangExtract) | Requires API calls to external LLMs. Defeats the purpose of a fast local tool. |
| GLiNER zero-shot NER | Cool but niche. Standard NER covers our needs. Can revisit later. |
| Faker synthetic data generation | Nice-to-have. Can be added later as a custom operator. |
| DICOM medical image support | Medical imaging is out of scope. |
| Lemma-based context matching | Our keyword lists already use root forms. spaCy lemmatization adds no value over exact match for our use case. |
| Stanza NLP engine | Redundant — we have ONNX-based transformer NER which is equivalent. |
| YAML no-code configuration | Nice-to-have for Phase 4. Not blocking parity. |

---

## Acceptance Criteria

- [ ] All 50 Presidio entity types have a Rust equivalent (pattern + validation)
- [ ] All checksum validations implemented (mod-97, Verhoeff, mod-11, weighted)
- [x] IPv6 detection added
- [x] Generic international phone detection added
- [x] Generic IBAN with country validation added
- [x] MAC_ADDRESS detection added
- [x] DATE_TIME detection added (context-gated)
- [x] LOCATION detection via NER model
- [ ] All 6 anonymization operators implemented
- [ ] AES encrypt/decrypt working
- [ ] `patterns.rs` refactored into `patterns/` module structure
- [ ] All new entities have tests
- [ ] No regressions in existing detection (`cargo test` passes)
- [ ] Benchmark shows no significant performance regression from additional patterns
- [ ] `list-entities` shows all ~56 entity types (50 Presidio + 6 Rust-only)
