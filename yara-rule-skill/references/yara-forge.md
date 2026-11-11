# YARA-Forge Reference

Source: [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge). Values below come from `yara-forge-config.yml`, `main/rule_processors.py`, `main/rule_output.py`, and `qa/rule_qa.py`.

YARA-Forge collects rules from 45+ vetted public repositories, normalizes their metadata, runs quality checks, and publishes weekly packages (core, extended, full). New sources are added only after vetting. Use this file when a rule should end up in a Forge package, or to explain why a rule landed in a given tier.

## Contents

- [Pipeline](#pipeline)
- [Metadata normalization](#metadata-normalization)
- [Score](#score)
- [Quality](#quality)
- [QA checks](#qa-checks)
- [Packages](#packages)
- [Checklist for Forge-ready rules](#checklist-for-forge-ready-rules)

## Pipeline

1. **Collect:** clone the configured repositories and parse all rules with plyara.
2. **Process:** rename, deduplicate, normalize metadata, derive tags and score.
3. **QA:** compile checks plus yaraQA; each issue lowers the rule's quality.
4. **Output:** write the three packages, filtered by score, quality, age, and importance.
5. **Validate:** compile each package; a package that fails to compile or is empty stops the build.

## Metadata normalization

Forge rewrites every rule's metadata into one schema, in this order: `description`, `author`, `id`, `date`, `modified`, `old_rule_name`, `reference`, `source_url`, `license_url`, `hash`, `logic_hash`, `score`, `quality`, `tags`.

| Output field | Taken from | If absent |
|--------------|-----------|-----------|
| Rule name | Original name, prefixed with the source repository (`SIGNATURE_BASE_...`) | — |
| `description` | `description`, `desc`, `details`, `information`, `info`, `notes`, `abstract`, `explanation`, `rationale`; else any value starting with "Detects "; else a threat-name field (`threat_name`, `threat`, `malware`, `threat_family`, ...) turned into "Detects ..." | "No description has been set in the source file - <repo description>" |
| `author` | `author`, `authors`, `writer`, `creator`, `created_by`, `copyright`, `made_by`, `contributor`, `contributed_by` | Repository author |
| `reference` | `reference`, `references`, `ref`, `url`, `source`, `link`, `website`, `webpage`, `report`; else any value starting with `http://` or `https://` | Rule file URL in the source repository |
| `date` | `date`, `created`, `created_at`, `creation_date`, `creation_time`, `creation`, `timestamp`, `time`, `datetime` (parsed, written as `YYYY-MM-DD`) | First commit date of the rule file |
| `modified` | `modified`, `last_modified`, `last_update`, `updated`, and similar | Last commit date of the rule file |
| `hash` | `hash`, `hashes`, `md5`, `sha1`, `sha256`, `sha512`, `sample`, `reference_sample`, numbered forms (`hash1`, `sha256_2`, ...) | — |
| `id` | An existing UUIDv5 in `id`, `uuid`, `rule_id`, ...; other `id` values move to `orig_id` | Deterministic UUIDv5 from the logic hash |
| `logic_hash` | Hash of strings and condition (plyara) | — |
| `tags` | Native rule tags, `tags`/`category`/`family`/`type`/`actor`/`mitre_attack`/... fields, CVE IDs and ATT&CK technique IDs (`T1059`) found in the description, and `FILE` when the condition has a header check, `filesize`, or ends with `at 0` | — |
| `score` | See [Score](#score) | 75 |
| `quality` | See [Quality](#quality) | — |

Rules with the same logic hash as an earlier rule are dropped as duplicates, unless another rule references them.

Writing the Style Guide's standard field names avoids relying on this mapping: other tools that consume your rules don't normalize.

## Score

Forge sets `score` in this order:

1. An explicit `score` metadata value (an integer, or a string holding one) wins.
2. Otherwise keywords in the metadata (all fields except `reference`), then in the rule name, decide:
   - `suspicious` or `susp_` → **65**
   - `hunting`, `experimental`, `test`, `testing`, `false positive`, `unstable`, `untested`, `unverified`, `unreliable`, `unconfirmed`, `hunt_` → **50**
3. Otherwise the base score **75**.

Matching is by substring, case-insensitive: "latest" contains "test" and drops a rule without explicit score to 50. **Always set `score` explicitly.**

Afterwards, rules that import the `elf` module get score 40 (full package only), and a curated list of noisy rules gets fixed scores.

## Quality

Quality measures how much Forge trusts a rule; it is separate from `score`.

- Starting value: the source repository's quality from the config (70-90 for current sources).
- Each QA issue subtracts by level: 1 → -2, 2 → -25, 3 → -70, 4 → -1000.
- Rules on the curated noisy-rules list lose additional points.

One level-2 issue takes a rule from a quality-90 repository to 65, below the core package threshold of 70.

## QA checks

| ID | Level | Check |
|----|-------|-------|
| `SI1` | 4 (critical) | Doesn't compile with YARA (yara-python), private rule dependencies included. The rule is excluded. Covers syntax errors, undefined identifiers, and external variables. |
| `SI2` | 3 (error) | Compiles only with warnings: Forge compiles with `error_on_warning=True`. Typical causes: regex with `.*`/`.+`/`.{n,}`, strings that "may slow down scanning", conditions that are always false. |
| yaraQA IDs | 1-3 | The per-rule checks in [yaraqa-checks.md](yaraqa-checks.md), with Forge's own regex timing for `PI1`. Forge calls yaraQA one rule at a time, so the rule set checks `MO1` and `DU1` never run. |

Forge writes every issue to `yara-forge-rule-issues.yml`, grouped by source repository. yaraQA is a pinned git submodule (`qa/yaraQA`), so yaraQA changes reach Forge only after the submodule is updated. As of November 2026 Forge pins a yaraQA version from before the `DS1` and `HS4` fixes, so it doesn't report those two yet.

## Packages

| Package | Minimum quality | Minimum score | Age (days) | Force include at importance | Force exclude below importance |
|---------|-----------------|---------------|------------|-----------------------------|--------------------------------|
| core | 70 | 65 | 1 to 2500 | ≥ 80 | < 50 |
| extended | 50 | 60 | 1 to 5000 | ≥ 70 | < 20 |
| full | 20 | 40 | 0 to 10000 | ≥ 50 | < 0 |

- **Age:** the maximum is measured from `date` (creation); the minimum from `modified`. A rule changed within the last day is left out of core and extended until the next build.
- **Importance:** a curated per-repository, per-file, or per-rule override. It can force a rule into a package despite low quality, or out of it.
- **Private rules** are included only where a public rule needs them.

Intended use: core for production with low false-positive tolerance, extended for broader hunting, full for research.

## Checklist for Forge-ready rules

- [ ] Compiles in YARA 4.x **without warnings** (`SI1`, `SI2`)
- [ ] No yaraQA issue of level 2 or higher
- [ ] Explicit `score` ≥ 65 for core (≥ 60 for extended)
- [ ] No words like "test", "experimental", or "hunting" in metadata unless the rule really is one (they only matter without an explicit score, but signal intent)
- [ ] Standard metadata names: `description`, `author`, `reference`, `date`, `modified`, `hash`
- [ ] No `elf` module unless needed (caps the score at 40)
- [ ] No external variables or modules that aren't available in standard YARA
