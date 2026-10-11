#!/usr/bin/env python3
"""Exercise installed CLI and local API contracts with fictional data and a temporary home."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise SystemExit(f"release smoke failed: {message}")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def stop_api_server(process):
    """Always reap the child, escalating only after bounded shutdown waits."""
    for action in [lambda: process.send_signal(signal.SIGINT), process.terminate, process.kill]:
        if process.poll() is None:
            try:
                action()
            except ProcessLookupError:
                pass
        try:
            return process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            continue
    require(False, "API server did not exit after kill")


def check_api_handoff(binary, smoke_home, environment):
    # Keep every request on loopback, independent of CI proxy settings.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirects()
    )
    mapping_path = smoke_home / "api-mapping.json"
    require(not mapping_path.exists(), "API mapping path already exists")

    def request(origin, path, body=None, timeout=3):
        headers = {} if body is None else {"Content-Type": "application/json"}
        outgoing = urllib.request.Request(origin + path, data=body, headers=headers)
        try:
            response = opener.open(outgoing, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read(1_000_001)
            require(len(payload) <= 1_000_000, f"API {path} response exceeded limit")
            return response.status, payload

    def verify(process, origin):
        def post(path, body, label, expected_status=200):
            require(process.poll() is None, f"API server exited before {label}")
            status, payload = request(origin, path, body)
            require(process.poll() is None, f"API server exited during {label}")
            require(
                status == expected_status,
                f"{label} {path} returned HTTP {status}: {payload.decode(errors='replace')}",
            )
            return payload

        # These source byte ranges match the route regressions. A separate
        # trailing email catches audit entries appended out of source order.
        for label, text, inner_type, url_span, inner_spans, following_spans in [
            (
                "email query",
                "Échec 📨 https://example.invalid/?email=ada%40example.invalid ; contact blair@example.invalid",
                "EMAIL_ADDRESS",
                ("URL", 12, 64),
                [("EMAIL_ADDRESS", 43, 64)],
                [("EMAIL_ADDRESS", 75, 96)],
            ),
            (
                "phone query",
                "Échec 📨 https://example.invalid/contact?tel=%2B33639980001",
                "FR_PHONE_NUMBER",
                ("URL", 12, 62),
                [("FR_PHONE_NUMBER", 48, 62)],
                [],
            ),
        ]:
            source = text.encode("utf-8")
            for entities in [None, ["URL", inner_type], ["URL"], [inner_type]]:
                case = f"{label} ({'default' if entities is None else ','.join(entities)})"
                analysis_request = {"text": text, "language": "en"}
                if entities is not None:
                    analysis_request["entities"] = entities
                analyzed = post(
                    "/analyze", json.dumps(analysis_request).encode(), case
                )
                # Embed the exact analyzer JSON, without sorting or pruning it.
                anonymize_request = (
                    b'{"text":' + json.dumps(text).encode()
                    + b',"analyzer_results":' + analyzed
                    + b',"anonymizers":{"DEFAULT":{"type":"mask","masking_char":"*"}}}'
                )
                anonymized = post("/anonymize", anonymize_request, case)
                if entities == [inner_type]:
                    expected_spans = inner_spans + following_spans
                elif entities == ["URL"]:
                    expected_spans = [url_span]
                else:
                    expected_spans = [url_span] + following_spans
                results = json.loads(analyzed)
                actual_spans = [
                    (item["entity_type"], item["start"], item["end"])
                    for item in results
                ]
                require(actual_spans == expected_spans, f"{case} changed source spans")
                expected_output = source
                for _, start, end in reversed(expected_spans):
                    require(source[start:end].isascii(), f"{case} fixture span is not ASCII")
                    expected_output = (
                        expected_output[:start] + b"*" * (end - start) + expected_output[end:]
                    )
                response = json.loads(anonymized)
                require(
                    response["text"].encode("utf-8") == expected_output,
                    f"{case} did not mask the exact complete spans",
                )
                expected_items = [
                    {
                        "operator": "mask", "entity_type": entity,
                        "start": start, "end": end, "text": "*" * (end - start),
                    }
                    for entity, start, end in expected_spans
                ]
                require(response["items"] == expected_items, f"{case} changed output item spans")
                for item in response["items"]:
                    require(
                        expected_output[item["start"]:item["end"]] == item["text"].encode(),
                        f"{case} item does not match its UTF-8 output range",
                    )

        # Invalid externally supplied overlaps must still be rejected.
        overlap = {
            "text": "call john@example.com now",
            "analyzer_results": [
                {"entity_type": "EMAIL_ADDRESS", "start": 5, "end": 21, "score": 0.9},
                {"entity_type": "PERSON", "start": 5, "end": 9, "score": 0.7},
            ],
            "anonymizers": {},
        }
        rejected = post(
            "/anonymize", json.dumps(overlap).encode(), "external overlap", 422
        )
        require(b"Overlapping analyzer results" in rejected, "API did not reject overlapping input")

    startup_failures = []
    for attempt in range(3):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        log_path = smoke_home / f"api-server-{attempt}.log"
        ready = False
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [str(binary), "--mapping", str(mapping_path), "api", "--port", str(port)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                cwd=smoke_home, env=environment,
            )
            try:
                deadline = time.monotonic() + 10
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        status, _ = request(
                            origin, "/health", timeout=min(0.5, max(0.01, deadline - time.monotonic()))
                        )
                    except (urllib.error.URLError, OSError):
                        time.sleep(0.05)
                        continue
                    if status == 200:
                        # Another listener can win the released port. A health
                        # response is insufficient if our child then exits.
                        try:
                            process.wait(timeout=0.2)
                        except subprocess.TimeoutExpired:
                            ready = True
                        break
                    time.sleep(0.05)
                if ready:
                    verify(process, origin)
            finally:
                exit_code = stop_api_server(process)
                require(not mapping_path.exists(), "API persisted its explicit mapping")
                require(
                    not (smoke_home / ".anon-pii" / "mapping.json").exists(),
                    "API persisted a default mapping",
                )
        diagnostics = log_path.read_text(errors="replace")
        if ready:
            # A clean exit also proves the tested child reached its bound
            # server loop, rather than failing to bind behind another listener.
            require(exit_code == 0, f"API server exited {exit_code}: {diagnostics}")
            return
        startup_failures.append(f"attempt {attempt + 1}: exit {exit_code}; {diagnostics}")
    require(False, "API server did not become ready: " + "; ".join(startup_failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    email = b"john@example.com"
    credential = b"ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA=="  # debug:example-password
    payload = b"Contact " + email + b"\nAuthorization: Basic " + credential + b"\n"

    with tempfile.TemporaryDirectory(prefix="anon-pii-release-smoke-") as directory:
        smoke_home = Path(directory)
        environment = os.environ.copy()
        environment["HOME"] = str(smoke_home)

        def run(arguments, data=b""):
            result = subprocess.run(
                [str(binary), *arguments],
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=smoke_home,
                env=environment,
                timeout=30,
                check=False,
            )
            require(
                result.returncode == 0,
                f"{arguments[0]} exited {result.returncode}: "
                f"{result.stderr.decode(errors='replace')}",
            )
            return result

        version = run(["--version"])
        require(
            version.stdout.strip() == f"anon-pii {args.version}".encode(),
            "binary version does not match the release tag",
        )

        # A nonexistent absolute command proves dry-run never attempts to spawn it.
        preview = run(
            ["run", "--dry-run", "--", str(smoke_home / "must-not-start")], payload
        )
        require(email not in preview.stdout, "preview retained the synthetic email")
        require(credential not in preview.stdout, "preview retained Basic credentials")
        require(b"[EMAIL_ADDRESS_" in preview.stdout, "preview omitted the email token")
        require(
            b"Authorization: Basic [AUTH_TOKEN_" in preview.stdout,
            "preview did not preserve the Basic scheme around its credential token",
        )
        require(preview.stdout.endswith(b"\n"), "preview lost the final newline")
        require(
            b"Unique entities detected: 2" in preview.stderr,
            "preview did not report both unique entities",
        )
        require(
            email not in preview.stderr and credential not in preview.stderr,
            "preview summary included original values",
        )

        restored = run(["run", "--", "cat"], payload)
        require(restored.stdout == payload, "run -- cat did not restore exact input bytes")

        # Also observe actual child stdin so a transparent passthrough cannot pass.
        observed = smoke_home / "child-input.txt"
        child = run(["run", "--", "tee", str(observed)], payload)
        require(child.stdout == payload, "observed roundtrip did not restore exact input")
        outgoing = observed.read_bytes()
        require(email not in outgoing, "child received the original email")
        require(credential not in outgoing, "child received original Basic credentials")
        require(b"[EMAIL_ADDRESS_" in outgoing, "child did not receive an email token")
        require(b"[AUTH_TOKEN_" in outgoing, "child did not receive a credential token")

        # Released builds promise ner-lite. Exercise the new ticket path from
        # each extracted archive, including exact source restoration.
        person = b"Camille verneuil"
        address = b"24 rue des Nuages 75016 ville-exemple"
        ticket = b"Je m'appelle " + person + b".\nAdresse : " + address + b".\n" + payload
        child = run(["--ner", "run", "--", "tee", str(observed)], ticket)
        require(child.stdout == ticket, "ticket roundtrip did not restore exact input")
        outgoing = observed.read_bytes()
        for entity, original in [
            (b"PERSON", person),
            (b"FR_ADDRESS", address),
            (b"EMAIL_ADDRESS", email),
            (b"AUTH_TOKEN", credential),
        ]:
            require(original not in outgoing, f"ticket child received original {entity!r}")
            require(b"[" + entity + b"_" in outgoing, f"ticket omitted {entity!r} token")

        # An inner detection must not leave the rest of a password visible.
        # Assemble fictional credential shapes so they cannot be mistaken for
        # live secrets in this source file.
        secret_key = b"ghp" + b"_" + b"A" * 36
        jwt = b"eyJhbGciOiJub25lIn0" + b"." + b"eyJzdWIiOiJleGFtcGxlIn0"
        password_prefix = "Réponse 📨 — ".encode()
        password_suffix = b"\r\nplease investigate.\n"
        for label, assignment in [
            (
                "quoted email fragment",
                b'password="private-prefix ada@example.invalid private-suffix"',
            ),
            ("quoted IP fragment", b"pwd='private-prefix 192.0.2.20 private-suffix'"),
            ("unquoted IP fragment", b"DB_PASSWORD=private-prefix192.0.2.20private-suffix"),
            (
                "quoted secret fragment",
                b'secret="private-prefix ' + secret_key + b' private-suffix"',
            ),
            ("quoted credential whitespace", b'token=" ' + jwt + b' "'),
            ("credential with ampersand suffix", b"token=" + jwt + b"&cc_last4=4242"),
            ("encoded assignment separator", b"password%3Dada@example.invalid"),
            ("encoded quotes", b"password=%22ada@example.invalid%22"),
            (
                "encoded separator before value colon",
                b"password%3Dprivate-prefix:ada@example.invalid",
            ),
            (
                "fullwidth separator before value colon",
                "password＝private-prefix:ada@example.invalid".encode(),
            ),
            (
                "escaped separator before value colon",
                rb"password\u003Dprivate-prefix:ada@example.invalid",
            ),
            (
                "encoded separator before value equals",
                b"password%3Dprivate-prefix=ada@example.invalid",
            ),
        ]:
            source = password_prefix + assignment + password_suffix
            expected = (
                re.escape(password_prefix)
                + rb"\[PASSWORD_[0-9a-f]{8}\]"
                + re.escape(password_suffix)
            )
            preview = run(["run", "--dry-run"], source)
            require(
                re.fullmatch(expected, preview.stdout) is not None,
                f"{label} preview did not mask the complete password assignment",
            )
            child = run(["run", "--", "tee", str(observed)], source)
            require(child.stdout == source, f"{label} roundtrip changed source bytes")
            require(
                re.fullmatch(expected, observed.read_bytes()) is not None,
                f"{label} sent part of the password assignment to the child",
            )

        # Preserve specific classifications when they cover the entire value.
        for entity, value in [
            (b"SECRET_KEY", secret_key),
            (b"AUTH_TOKEN", jwt),
            (b"EMAIL_ADDRESS", b"ada@example.invalid"),
        ]:
            for key_prefix, quote_suffix in [
                (b"token=", b""),
                (b"secret = '", b"'"),
                (b'password="', b'"'),
            ]:
                prefix = password_prefix + key_prefix
                suffix = quote_suffix + password_suffix
                source = prefix + value + suffix
                expected = (
                    re.escape(prefix)
                    + rb"\[" + entity + rb"_[0-9a-f]{8}\]"
                    + re.escape(suffix)
                )
                preview = run(["run", "--dry-run"], source)
                require(
                    re.fullmatch(expected, preview.stdout) is not None,
                    f"complete {entity!r} value lost its specific preview token",
                )
                child = run(["run", "--", "tee", str(observed)], source)
                require(child.stdout == source, "complete-value roundtrip changed source bytes")
                require(
                    re.fullmatch(expected, observed.read_bytes()) is not None,
                    f"complete {entity!r} value lost its specific child-input token",
                )

        # Incorrect regex offsets can still roundtrip perfectly while leaving
        # part of a configured value visible. Check complete child-input spans.
        recognizers = smoke_home / "recognizers.yml"
        for pattern, source, prefix in [
            (".abb|b", b"zabb", b""),
            ("(?:..acbb|b)a(?:c|d)", b"xzbacbbac", b"x"),
            (".abb|b", "🧪 za%62%62".encode(), "🧪 ".encode()),
        ]:
            recognizers.write_text(
                "recognizers:\n  - name: Synthetic value\n"
                "    entity_type: SYNTHETIC_VALUE\n    patterns:\n"
                f"      - regex: '{pattern}'\n        score: 1.0\n",
                encoding="utf-8",
            )
            flags = ["--config", str(recognizers), "--threshold", "1"]
            expected = re.escape(prefix) + rb"\[SYNTHETIC_VALUE_[0-9a-f]{8}\]"
            preview = run([*flags, "run", "--dry-run"], source)
            require(
                re.fullmatch(expected, preview.stdout) is not None,
                f"custom recognizer {pattern!r} preview did not mask the full span",
            )
            child = run([*flags, "run", "--", "tee", str(observed)], source)
            require(child.stdout == source, "custom regex roundtrip changed source bytes")
            require(
                re.fullmatch(expected, observed.read_bytes()) is not None,
                f"custom recognizer {pattern!r} sent an incomplete span to the child",
            )

        # Fictional checksum-valid fixtures: casing must not leave an IBAN
        # visible or consume the adjacent prose. French print format has fixed
        # fields; generic lowercase support is deliberately compact-only.
        for label, entity, iban, prefix in [
            ("generic lowercase", "IBAN_CODE", "gb82west12345698765432", "Échec — IBAN "),
            ("generic mixed case", "IBAN_CODE", "gB82WeSt12345698765432", "Échec — IBAN "),
            ("French print lowercase", "FR_IBAN", "fr14 2004 1010 0505 0001 3m02 606", "Échec — "),
            ("French print mixed case", "FR_IBAN", "Fr14 2004 1010 0505 0001 3M02 606", "Échec — "),
        ]:
            suffix = " please investigate.\n"
            source = (prefix + iban + suffix).encode()
            expected = (
                re.escape(prefix.encode())
                + rb"\[" + entity.encode() + rb"_[0-9a-f]{8}\]"
                + re.escape(suffix.encode())
            )
            preview = run(["run", "--dry-run"], source)
            require(
                re.fullmatch(expected, preview.stdout) is not None,
                f"{label} IBAN preview did not mask the exact span",
            )
            child = run(["run", "--", "tee", str(observed)], source)
            require(child.stdout == source, f"{label} IBAN roundtrip changed source bytes")
            require(
                re.fullmatch(expected, observed.read_bytes()) is not None,
                f"{label} IBAN child input did not preserve the exact token span",
            )

        for label, text in [
            ("generic invalid checksum", "IBAN gb83west12345698765432"),
            ("French print invalid checksum", "IBAN fr14 2004 1010 0505 0001 3m02 607"),
            ("generic lowercase without context", "code gb82west12345698765432 here"),
            ("generic mixed case without context", "code gB82WeSt12345698765432 here"),
            ("unsupported generic grouped lowercase", "IBAN gb82 west 1234 5698 7654 32"),
        ]:
            source = text.encode()
            preview = run(["run", "--dry-run"], source)
            require(preview.stdout == source, f"{label} control changed in preview")
            child = run(["run", "--", "tee", str(observed)], source)
            require(child.stdout == source, f"{label} control changed during roundtrip")
            require(observed.read_bytes() == source, f"{label} control changed in child input")

        # Test the complete wrapped source span, including its line ending and
        # indentation. Separate preview/run invocations use fresh token IDs.
        text_prefix = "Réponse 😀 — contact ".encode()
        text_suffix = b"; please investigate.\n"
        sql_prefix = r"INSERT INTO tickets VALUES (E'Préfixe 😀 it\'s ".encode()
        sql_suffix = rb"; suffix\nunchanged');" + b"\r\n"
        for label, flags, prefix, address, suffix in [
            (
                "LF-wrapped email",
                [],
                text_prefix,
                b"ada@\nexample.invalid",
                text_suffix,
            ),
            (
                "CRLF/tab-wrapped Unicode email",
                [],
                text_prefix,
                "iñes@\r\n\texample.invalid".encode(),
                text_suffix,
            ),
            (
                "PostgreSQL E-string named controls",
                ["--format", "sql"],
                sql_prefix,
                rb"ada@\r\n\texample.invalid",
                sql_suffix,
            ),
        ]:
            source = prefix + address + suffix
            expected = (
                re.escape(prefix)
                + rb"\[EMAIL_ADDRESS_[0-9a-f]{8}\]"
                + re.escape(suffix)
            )
            preview = run([*flags, "run", "--dry-run"], source)
            require(
                re.fullmatch(expected, preview.stdout) is not None,
                f"{label} preview did not mask the exact source span",
            )
            child = run([*flags, "run", "--", "tee", str(observed)], source)
            require(child.stdout == source, f"{label} roundtrip changed source bytes")
            require(
                re.fullmatch(expected, observed.read_bytes()) is not None,
                f"{label} child input did not preserve the exact token span",
            )

        # Blank lines and malformed domains must not create a wrapped email.
        # SQL named controls apply to E-strings, not ordinary/dollar quotes or
        # a doubled backslash that represents literal text rather than a control.
        for label, flags, source in [
            ("wrapped email across a blank line", [], b"ada@\n\nexample.invalid"),
            ("wrapped email with malformed domain", [], b"ada@\nexample.invalid_extra"),
            (
                "SQL standard-quoted named controls",
                ["--format", "sql"],
                rb"SELECT 'ada@\r\n\texample.invalid';",
            ),
            (
                "SQL dollar-quoted named controls",
                ["--format", "sql"],
                rb"SELECT $body$ada@\r\n\texample.invalid$body$;",
            ),
            (
                "SQL E-string doubled backslashes",
                ["--format", "sql"],
                rb"SELECT E'ada@\\r\\n\\texample.invalid';",
            ),
        ]:
            preview = run([*flags, "run", "--dry-run"], source)
            require(preview.stdout == source, f"{label} control changed in preview")
            child = run([*flags, "run", "--", "tee", str(observed)], source)
            require(child.stdout == source, f"{label} control changed during roundtrip")
            require(observed.read_bytes() == source, f"{label} control changed in child input")

        check_api_handoff(binary, smoke_home, environment)

        require(
            not (smoke_home / ".anon-pii" / "mapping.json").exists(),
            "transaction persisted a mapping file",
        )

    print(
        f"Release smoke passed: anon-pii {args.version}; "
        "preview, roundtrip, support ticket, custom regex spans, IBAN casing, "
        "wrapped emails, SQL E-string controls, complete passwords, specific credentials, "
        "local API analyze/anonymize handoff"
    )


if __name__ == "__main__":
    main()
