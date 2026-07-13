#!/usr/bin/env python3
"""Compare pinned anon-pii and censgate/redact exact-span reports.

The adapter intentionally uses only the Python standard library. It verifies
clean source revisions, generates anon-pii's report in its own checkout, and
builds the redact release binary from the supplied checkout before measuring.
It does not download dependencies or make tracked source changes.
"""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


SCORE_SCALE = 1_000_000


class ComparisonError(Exception):
    pass


def parse_args():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run a pinned exact-span comparison against censgate/redact."
    )
    parser.add_argument("--redact-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    args.anon_repo = root
    args.corpus = root / "testdata/quality/v1.json"
    args.manifest = root / "testdata/quality/comparison-redact-v1.json"
    return args


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComparisonError("failed to load {}: {}".format(path, error)) from error


def load_json_text(source, label):
    try:
        return json.loads(source)
    except json.JSONDecodeError as error:
        raise ComparisonError("{} emitted invalid JSON: {}".format(label, error)) from error


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ComparisonError("failed to hash {}: {}".format(path, error)) from error


def git_output(repo, *args):
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ComparisonError(
            "git check failed for {}: {}".format(repo, detail.strip())
        ) from error
    return completed.stdout.strip()


def pinned_revision(repo):
    revision = git_output(repo, "rev-parse", "HEAD")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ComparisonError("{} is not pinned to a full Git commit".format(repo))
    dirty = git_output(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise ComparisonError(
            "{} has tracked changes; compare clean pinned revisions".format(repo)
        )
    return revision


def require_github_remote(repo, project):
    remote = git_output(repo, "remote", "get-url", "origin")
    normalized = remote.lower().rstrip("/")
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    if not normalized.endswith(
        ("github.com/{}".format(project), "github.com:{}".format(project))
    ):
        raise ComparisonError(
            "{} origin {!r} is not github.com/{}".format(repo, remote, project)
        )
    return remote


def require_object(value, label):
    if not isinstance(value, dict):
        raise ComparisonError("{} must be a JSON object".format(label))
    return value


def require_list(value, label):
    if not isinstance(value, list):
        raise ComparisonError("{} must be a JSON array".format(label))
    return value


def index_unique(values, key, label):
    result = {}
    for index, value in enumerate(values):
        value = require_object(value, "{}[{}]".format(label, index))
        identifier = value.get(key)
        if not isinstance(identifier, str) or not identifier:
            raise ComparisonError("{} contains an invalid {}".format(label, key))
        if identifier in result:
            raise ComparisonError("{} contains duplicate {} {!r}".format(label, key, identifier))
        result[identifier] = value
    return result


def validate_manifest(manifest, corpus):
    if manifest.get("schema_version") != 1:
        raise ComparisonError("comparison manifest schema_version must be 1")
    if manifest.get("corpus_version") != corpus.get("corpus_version"):
        raise ComparisonError("comparison manifest and corpus versions differ")
    if manifest.get("matching") != "exact neutral-family and UTF-8 byte span":
        raise ComparisonError("comparison manifest has an unsupported matching rule")
    selection = require_object(manifest.get("selection"), "manifest selection")
    if selection.get("rule") != (
        "include a case when every expected entity type is in "
        "included_expected_entity_types"
    ):
        raise ComparisonError("comparison manifest has an unsupported selection rule")
    included_types = require_list(
        selection.get("included_expected_entity_types"),
        "manifest included_expected_entity_types",
    )
    if (
        not included_types
        or len(included_types) != len(set(included_types))
        or not all(isinstance(entity_type, str) and entity_type for entity_type in included_types)
    ):
        raise ComparisonError("included expected entity types must be non-empty and unique")

    corpus_cases = require_list(corpus.get("cases"), "corpus cases")
    included_type_set = set(included_types)
    case_ids = []
    excluded_case_ids = []
    for index, case in enumerate(corpus_cases):
        case = require_object(case, "corpus cases[{}]".format(index))
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise ComparisonError("corpus cases[{}] has an invalid id".format(index))
        expected = require_list(case.get("expected"), "corpus case expected")
        expected_types = []
        for span_index, span in enumerate(expected):
            span = require_object(
                span, "corpus cases[{}].expected[{}]".format(index, span_index)
            )
            expected_types.append(span.get("entity_type"))
        target = (
            case_ids
            if all(entity_type in included_type_set for entity_type in expected_types)
            else excluded_case_ids
        )
        target.append(case_id)
    if len(case_ids) != selection.get("expected_case_count"):
        raise ComparisonError(
            "selection produced {} cases, expected {}".format(
                len(case_ids), selection.get("expected_case_count")
            )
        )
    family_maps = require_object(manifest.get("family_maps"), "manifest family_maps")
    for tool in ("expected", "anon_pii", "censgate_redact"):
        mapping = require_object(family_maps.get(tool), "family map {}".format(tool))
        if not all(
            isinstance(entity_type, str)
            and entity_type
            and isinstance(family, str)
            and family
            for entity_type, family in mapping.items()
        ):
            raise ComparisonError("family map {} has an invalid entry".format(tool))
    missing_expected_maps = included_type_set - set(family_maps["expected"])
    if missing_expected_maps:
        raise ComparisonError(
            "expected family map is missing selected types {}".format(
                sorted(missing_expected_maps)
            )
        )
    return case_ids, excluded_case_ids, included_types, family_maps


def validate_source_span(input_text, span, raw_key, label):
    try:
        start = span["start"]
        end = span["end"]
        raw = span[raw_key]
    except KeyError as error:
        raise ComparisonError("{} is missing {}".format(label, error)) from error
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or start >= end:
        raise ComparisonError("{} has an invalid span {}..{}".format(label, start, end))
    if not isinstance(raw, str):
        raise ComparisonError("{} has a non-string raw value".format(label))
    source = input_text.encode("utf-8")
    try:
        actual = source[start:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ComparisonError("{} is not on UTF-8 byte boundaries".format(label)) from error
    if actual != raw:
        raise ComparisonError(
            "{} labels {!r}, but source bytes contain {!r}".format(label, raw, actual)
        )


def normalize_spans(
    input_text,
    spans,
    family_map,
    raw_key,
    label,
    strict_types=False,
    native_keys=(),
):
    normalized = []
    unmapped = set()
    for index, span in enumerate(require_list(spans, label)):
        span = require_object(span, "{}[{}]".format(label, index))
        validate_source_span(input_text, span, raw_key, "{}[{}]".format(label, index))
        entity_type = span.get("entity_type")
        if not isinstance(entity_type, str) or not entity_type:
            raise ComparisonError("{}[{}] has an invalid entity_type".format(label, index))
        family = family_map.get(entity_type)
        if family is None:
            if strict_types:
                raise ComparisonError(
                    "{}[{}] uses unmapped expected type {!r}".format(label, index, entity_type)
                )
            family = "unmapped:{}".format(entity_type)
            unmapped.add(entity_type)
        record = {
            "entity_type": entity_type,
            "family": family,
            "start": span["start"],
            "end": span["end"],
            "raw": span[raw_key],
        }
        native = {key: span.get(key) for key in native_keys}
        if native:
            record["native"] = native
        normalized.append(record)
    normalized.sort(
        key=lambda span: (
            span["start"],
            span["end"],
            span["family"],
            span["entity_type"],
            span["raw"],
        )
    )
    return normalized, unmapped


def span_counter(case_id, spans, label_key, label=None):
    return collections.Counter(
        (case_id, span[label_key], span["start"], span["end"])
        for span in spans
        if label is None or span[label_key] == label
    )


def score(expected, predicted):
    true_positive = sum((expected & predicted).values())
    false_positive = sum((predicted - expected).values())
    false_negative = sum((expected - predicted).values())

    def ratio(numerator, denominator):
        return None if denominator == 0 else numerator * SCORE_SCALE // denominator

    return {
        "tp": true_positive,
        "fp": false_positive,
        "fn": false_negative,
        "precision_ppm": ratio(true_positive, true_positive + false_positive),
        "recall_ppm": ratio(true_positive, true_positive + false_negative),
    }


def tool_metrics(case_records, tool, label_key):
    expected = collections.Counter()
    predicted = collections.Counter()
    families = set()
    for case in case_records:
        expected.update(span_counter(case["id"], case["expected"], label_key))
        predicted.update(
            span_counter(case["id"], case["predictions"][tool], label_key)
        )
        families.update(span[label_key] for span in case["expected"])
        families.update(span[label_key] for span in case["predictions"][tool])
    per_label = {}
    for label in sorted(families):
        expected_label = collections.Counter(
            {key: count for key, count in expected.items() if key[1] == label}
        )
        predicted_label = collections.Counter(
            {key: count for key, count in predicted.items() if key[1] == label}
        )
        per_label[label] = score(expected_label, predicted_label)
    return {"overall": score(expected, predicted), "by_label": per_label}


def generate_anon_report(repo):
    command = [
        "cargo",
        "run",
        "--locked",
        "--quiet",
        "--example",
        "quality_report",
        "--",
        "--json",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ComparisonError(
            "anon quality report failed: {}".format(detail.strip())
        ) from error
    return require_object(load_json_text(completed.stdout, "anon quality report"), "anon report"), completed.stdout.encode("utf-8")


def build_redact(repo):
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "redact-cli",
        "--bin",
        "redact",
    ]
    try:
        subprocess.run(
            command,
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ComparisonError("redact build failed: {}".format(detail.strip())) from error
    binary = repo / "target/release/redact"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ComparisonError("redact build did not produce {}".format(binary))
    return binary


def run_redact(binary, input_text):
    try:
        completed = subprocess.run(
            [str(binary), "--format", "json", "--language", "en", "analyze"],
            input=input_text,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise ComparisonError("redact analyze failed: {}".format(detail.strip())) from error
    report = require_object(load_json_text(completed.stdout, "redact"), "redact report")
    metadata = require_object(report.get("metadata"), "redact metadata")
    if metadata.get("language") != "en":
        raise ComparisonError("redact report did not confirm the requested en language")
    if metadata.get("recognizers_used") != 1:
        raise ComparisonError("redact report did not use exactly one default recognizer")
    detections = require_list(report.get("detected_entities"), "redact detected_entities")
    for index, detection in enumerate(detections):
        detection = require_object(detection, "redact detected_entities[{}]".format(index))
        if detection.get("recognizer_name") != "PatternRecognizer":
            raise ComparisonError(
                "redact detection {} did not come from PatternRecognizer".format(index)
            )
        if not isinstance(detection.get("score"), (int, float)):
            raise ComparisonError("redact detection {} has an invalid score".format(index))
    return detections, {
        "language": metadata["language"],
        "recognizers_used": metadata["recognizers_used"],
    }


def build_report(args):
    args.anon_repo = args.anon_repo.resolve()
    args.redact_repo = args.redact_repo.resolve()
    anon_revision = pinned_revision(args.anon_repo)
    redact_revision = pinned_revision(args.redact_repo)
    require_github_remote(args.anon_repo, "tcheud/anon-pii")
    require_github_remote(args.redact_repo, "censgate/redact")

    corpus = require_object(load_json(args.corpus), "corpus")
    manifest = require_object(load_json(args.manifest), "manifest")
    case_ids, excluded_case_ids, included_types, family_maps = validate_manifest(
        manifest, corpus
    )
    configurations = require_object(
        manifest.get("configurations"), "manifest configurations"
    )
    anon_configuration = require_object(
        configurations.get("anon_pii"), "anon configuration"
    )
    redact_configuration = require_object(
        configurations.get("censgate_redact"), "redact configuration"
    )
    threshold = anon_configuration.get("threshold")
    if not isinstance(threshold, (int, float)) or not 0.0 <= threshold <= 1.0:
        raise ComparisonError("anon comparison threshold must be between zero and one")

    anon_report, anon_report_bytes = generate_anon_report(args.anon_repo)
    redact_binary = build_redact(args.redact_repo)
    if pinned_revision(args.anon_repo) != anon_revision:
        raise ComparisonError("anon revision changed while generating the report")
    if pinned_revision(args.redact_repo) != redact_revision:
        raise ComparisonError("redact revision changed while building the adapter binary")

    corpus_sha256 = sha256_file(args.corpus)
    if anon_report.get("schema_version") != corpus.get("schema_version"):
        raise ComparisonError("anon report and corpus schema versions differ")
    if anon_report.get("corpus_version") != corpus.get("corpus_version"):
        raise ComparisonError("anon report and corpus versions differ")
    if anon_report.get("corpus_sha256") != corpus_sha256:
        raise ComparisonError("anon report was not generated from the selected corpus bytes")
    if anon_report.get("profile_features") != anon_configuration.get("features"):
        raise ComparisonError("anon report features differ from the comparison manifest")
    expected_threshold = round(float(threshold) * SCORE_SCALE)
    if anon_report.get("threshold_ppm") != expected_threshold:
        raise ComparisonError("anon report threshold differs from the comparison manifest")

    corpus_cases = index_unique(
        require_list(corpus.get("cases"), "corpus cases"), "id", "corpus cases"
    )
    anon_cases = index_unique(
        require_list(anon_report.get("cases"), "anon report cases"),
        "id",
        "anon report cases",
    )
    if set(anon_cases) != set(corpus_cases):
        raise ComparisonError("anon report case ids differ from the corpus")
    expected_span_count = sum(
        len(require_list(case.get("expected"), "corpus case expected"))
        for case in corpus_cases.values()
    )
    if anon_report.get("case_count") != len(corpus_cases):
        raise ComparisonError("anon report case count differs from the corpus")
    if anon_report.get("expected_span_count") != expected_span_count:
        raise ComparisonError("anon report span count differs from the corpus")

    cases = []
    unmapped = {"anon_pii": set(), "censgate_redact": set()}
    for case_id in case_ids:
        if case_id not in corpus_cases:
            raise ComparisonError("manifest case {!r} is absent from the corpus".format(case_id))
        if case_id not in anon_cases:
            raise ComparisonError("manifest case {!r} is absent from the anon report".format(case_id))
        corpus_case = corpus_cases[case_id]
        anon_case = anon_cases[case_id]
        input_text = corpus_case.get("input")
        if not isinstance(input_text, str):
            raise ComparisonError("comparison case {!r} must contain text".format(case_id))
        if anon_case.get("expected") != corpus_case.get("expected"):
            raise ComparisonError("anon report labels differ for case {!r}".format(case_id))

        expected, _ = normalize_spans(
            input_text,
            corpus_case.get("expected"),
            family_maps["expected"],
            "raw",
            "{} expected".format(case_id),
            strict_types=True,
        )
        anon_predictions, anon_unknown = normalize_spans(
            input_text,
            anon_case.get("predicted", []),
            family_maps["anon_pii"],
            "raw",
            "{} anon predictions".format(case_id),
        )
        redact_native, redact_metadata = run_redact(redact_binary, input_text)
        redact_predictions, redact_unknown = normalize_spans(
            input_text,
            redact_native,
            family_maps["censgate_redact"],
            "text",
            "{} redact predictions".format(case_id),
            native_keys=("score", "recognizer_name"),
        )
        unmapped["anon_pii"].update(anon_unknown)
        unmapped["censgate_redact"].update(redact_unknown)
        cases.append(
            {
                "id": case_id,
                "input": input_text,
                "expected": expected,
                "predictions": {
                    "anon_pii": anon_predictions,
                    "censgate_redact": redact_predictions,
                },
                "native_metadata": {"censgate_redact": redact_metadata},
                "metrics": {
                    "anon_pii": score(
                        span_counter(case_id, expected, "family"),
                        span_counter(case_id, anon_predictions, "family"),
                    ),
                    "censgate_redact": score(
                        span_counter(case_id, expected, "family"),
                        span_counter(case_id, redact_predictions, "family"),
                    ),
                },
            }
        )

    return {
        "schema_version": 1,
        "comparison_version": manifest.get("comparison_version"),
        "scope": {
            "case_count": len(cases),
            "matching": manifest.get("matching"),
            "selection_note": manifest.get("selection_note"),
            "selection_rule": manifest["selection"]["rule"],
            "included_expected_entity_types": included_types,
            "included_case_ids": case_ids,
            "excluded_case_ids": excluded_case_ids,
            "ranking": "none",
        },
        "inputs": {
            "corpus": {
                "path": "testdata/quality/v1.json",
                "version": corpus.get("corpus_version"),
                "sha256": corpus_sha256,
            },
            "manifest": {
                "path": "testdata/quality/comparison-redact-v1.json",
                "sha256": sha256_file(args.manifest),
            },
            "anon_report_sha256": sha256_bytes(anon_report_bytes),
        },
        "tools": {
            "anon_pii": {
                "repository": "https://github.com/tcheuD/anon-pii",
                "revision": anon_revision,
                "configuration": anon_configuration,
                "command": "cargo run --locked --quiet --example quality_report -- --json",
                "prediction_fields": ["entity_type", "start", "end", "raw"],
                "unmapped_entity_types": sorted(unmapped["anon_pii"]),
            },
            "censgate_redact": {
                "repository": "https://github.com/censgate/redact",
                "revision": redact_revision,
                "configuration": redact_configuration,
                "build_command": "cargo build --locked --release -p redact-cli --bin redact",
                "command": "redact --format json --language en analyze < case-input",
                "binary_sha256": sha256_file(redact_binary),
                "prediction_fields": [
                    "entity_type",
                    "start",
                    "end",
                    "text",
                    "score",
                    "recognizer_name",
                ],
                "unmapped_entity_types": sorted(unmapped["censgate_redact"]),
            },
        },
        "metrics": {
            "anon_pii": tool_metrics(cases, "anon_pii", "family"),
            "censgate_redact": tool_metrics(cases, "censgate_redact", "family"),
        },
        "cases": cases,
    }


def write_report(report, output):
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as error:
        raise ComparisonError("failed to write {}: {}".format(output, error)) from error


def main():
    try:
        args = parse_args()
        write_report(build_report(args), args.output)
    except ComparisonError as error:
        print("comparison failed: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
