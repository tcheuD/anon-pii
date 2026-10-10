#!/usr/bin/env python3
"""Exercise the installed CLI contract using fictional data and a temporary home."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise SystemExit(f"release smoke failed: {message}")


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

        require(
            not (smoke_home / ".anon-pii" / "mapping.json").exists(),
            "transaction persisted a mapping file",
        )

    print(
        f"Release smoke passed: anon-pii {args.version}; "
        "preview, roundtrip, support ticket, custom regex spans, IBAN casing"
    )


if __name__ == "__main__":
    main()
