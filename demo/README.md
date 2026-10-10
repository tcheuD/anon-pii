# Public Demos

These demos use fictional data only. Email domains use `example.invalid`, IP
addresses use documentation ranges, and card numbers are payment-network test
values.

Tracked demo assets:

- `samples/support-ticket.txt` shows a support-ticket workflow.
- `samples/support-ticket-fr.txt` includes a fictional introduced name, French
  address, email, and Basic credential.
- `ticket-reply.py` simulates a useful reply locally using the tokens it receives.
- `samples/incident-log.txt` shows log-style incident data.
- `samples/queries.sql` shows SQL anonymization.
- `samples/passengers.csv` shows CSV anonymization.
- `record.sh` runs a local terminal demo from a fresh checkout.
- `hero.tape` is the VHS source for the generated hero recording.

The main demo previews a fictional support ticket, then uses `run -- cat` to
restore the original values locally. It needs no AI tool or API key and saves
no mapping file. Install the CLI using the [installation guide](../README.md#installation).

Generated assets such as `hero.gif`, terminal casts, temporary maps, and
intermediate anonymized files are ignored. Record with your installed binary:

```bash
ANON_PII_BIN="$(command -v anon-pii)" demo/record.sh
ANON_PII_BIN="$(command -v anon-pii)" vhs demo/hero.tape
```

Without `ANON_PII_BIN`, the script builds and runs the current checkout through
Cargo. Try the samples directly with an installed CLI:

```bash
# Preview locally without a child command or a saved mapping
anon-pii run --dry-run < demo/samples/support-ticket.txt

# Exercise a complete local roundtrip; cat echoes the anonymized input
anon-pii run -- cat < demo/samples/support-ticket.txt

```

The preview shows detected values as tokens. The local roundtrip prints the
original ticket because the child echoes its tokenized stdin and anon-pii
restores known tokens in stdout. Review the preview for missed sensitive values
before substituting your own AI command; see the [first roundtrip guide](../README.md#first-roundtrip).

For a reply that uses the ticket's references, install a release binary or build
with `--features ner-lite`, then run:

```bash
anon-pii --ner run --dry-run < demo/samples/support-ticket-fr.txt
anon-pii --ner run -- python3 demo/ticket-reply.py < demo/samples/support-ticket-fr.txt
```

The Python simulator prints its actual tokenized input on stderr, then emits
a deterministic suggested follow-up on stdout. `anon-pii` restores the name,
email, and address in that reply. Python 3 is required; no AI service or network
is involved. See the [support-ticket guide](../docs/support-ticket.md).

Detached workflows remain available with a dedicated mapping file:

```bash
mkdir -p demo/tmp
anon-pii -i demo/samples/support-ticket.txt --mapping demo/tmp/demo-map.json
anon-pii --format sql -i demo/samples/queries.sql --mapping demo/tmp/demo-map.json
anon-pii --format csv -i demo/samples/passengers.csv --mapping demo/tmp/demo-map.json
```
