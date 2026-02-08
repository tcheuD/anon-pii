# Ticket #32: Expand Heuristic Dictionary with INSEE First Names

**Priority:** High
**Complexity:** Low
**Status:** ~~TODO~~ DONE (FIXED)
**Files:** `src/ner/heuristic.rs`, new `scripts/build_names.py`

## Description

The heuristic NER detector (`--features ner-lite`) uses a hand-curated dictionary of ~350 French and English first names. This is the #1 source of missed PERSON detections -- any name not in the list is invisible to the heuristic.

INSEE publishes every first name given to children born in France since 1900. Expanding from 350 to 2000+ names covers 99%+ of French people alive today, at zero runtime cost (it's a `const` array compiled into the binary).

## Data Source

- **URL:** https://www.insee.fr/fr/statistiques/8595130
- **Also on:** https://www.data.gouv.fr/datasets/fichier-des-prenoms-depuis-1900
- **Format:** CSV (`nat2024.csv`), columns: `sexe`, `preusuel`, `annais`, `nombre`
- **License:** Licence Ouverte v2.0 (fully open, commercial use OK)
- **Size:** ~711,000 rows (name x year x sex), ~30,000-35,000 unique names
- **Caveat:** Accents are absent from the file ("CELINE" not "CELINE"). Pre-1946, names must have been given 20+ times. Rare names grouped under `_PRENOMS_RARES_`.

## Implementation

### Step 1: Build script

Create `scripts/build_names.py` that:

1. Downloads the INSEE national CSV
2. Extracts unique values from the `PREUSUEL` column
3. Filters out `_PRENOMS_RARES_` and single-character entries
4. Ranks by total count (sum of `nombre` across all years)
5. Takes the top N names (default N=2000)
6. Applies title-case normalization ("JEAN-PIERRE" -> "Jean-Pierre")
7. Adds accented variants where possible (e.g., "GAELLE" -> "Gaelle" + "Gaelle")
8. Outputs a Rust `const` array to stdout or a file

```bash
uv run scripts/build_names.py --top 2000 > src/ner/names_insee.rs
```

### Step 2: Integrate into heuristic.rs

Replace the existing `FRENCH_FIRST_NAMES` array with an include:

```rust
// src/ner/heuristic.rs
include!("names_insee.rs");
// or
mod names_insee;
use names_insee::INSEE_FIRST_NAMES;
```

Keep the existing `ENGLISH_FIRST_NAMES` array alongside for coverage of international names in a French aviation context (English-speaking crew, passengers).

### Step 3: Accent handling

The INSEE file lacks accents. Two approaches:

- **Option A (simple):** Case-insensitive matching. "GAELLE" matches "Gaelle" and "Gaelle". Already partially implemented in `is_known_first_name()`.
- **Option B (better):** Maintain a separate accent-aware mapping. Build from community data or manual curation for the top 200 accented names (Rene/Rene, Noel/Noel, Celine/Celine, etc.).

Recommend Option A for v1, Option B as follow-up.

### Step 4: Compile-time vs runtime

Two options for shipping the name list:

- **Compile-time (recommended):** `const INSEE_NAMES: &[&str] = &[...]` baked into the binary. Zero runtime cost, no file I/O. Binary size increases by ~40-80 KB (2000 names x ~20 bytes avg).
- **Runtime:** Load from `~/.anon/names/insee.txt` at startup. More flexible but adds I/O and a file dependency.

## Expected Impact

| Metric | Before | After |
|--------|--------|-------|
| French first names in dictionary | ~350 | ~2000+ |
| Estimated PERSON recall (heuristic) | ~85% | ~98%+ |
| Runtime cost | 0 | 0 (const array) |
| Binary size increase | 0 | ~40-80 KB |

## Acceptance Criteria

- [ ] `scripts/build_names.py` downloads INSEE data and generates Rust const array
- [ ] Top 2000 French first names compiled into `ner-lite` binary
- [ ] Existing `ENGLISH_FIRST_NAMES` preserved alongside
- [ ] `cargo test --features ner-lite` passes (no regressions)
- [ ] No real PII in committed code (only public INSEE statistical data)
- [ ] Benchmark shows no measurable performance regression

## Depends On

Nothing. This is independent and can be done immediately.

## Blocks

- Ticket #33 (fine-tuned model) -- a stronger heuristic reduces the urgency for ML
