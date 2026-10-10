#!/usr/bin/env python3
"""Local, deterministic reply simulation. No AI service or network access."""

import re
import sys


def main():
    ticket = sys.stdin.read()
    # Deliberately show the actual child input so the handoff can be inspected.
    # anon-pii passes child stderr through unchanged.
    print("--- Local reply simulator received ---", file=sys.stderr)
    print(ticket, file=sys.stderr, end="" if ticket.endswith("\n") else "\n")
    required = ("PERSON", "EMAIL_ADDRESS", "FR_ADDRESS", "AUTH_TOKEN")
    tokens = {}
    for entity in required:
        match = re.search(r"\[" + entity + r"_[0-9a-f]{8}\]", ticket)
        if match is None:
            print(
                f"Expected a {entity} token. Use the fictional French sample "
                "with anon-pii --ner and a ner-lite build.",
                file=sys.stderr,
            )
            return 2
        tokens[entity] = match.group(0)

    print("Local simulation — this is not an AI diagnosis.")
    print(f"For {tokens['PERSON']}, contact {tokens['EMAIL_ADDRESS']}.")
    print(f"Confirm the delivery address: {tokens['FR_ADDRESS']}.")
    print("For CASE-2042, compare the request IDs and retry timestamps before")
    print("deciding whether the duplicate is in the UI or the delivery service.")
    print("Keep authentication credentials out of the customer reply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
