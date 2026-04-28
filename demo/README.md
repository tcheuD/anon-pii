# Public Demos

These demos use fictional data only. Email domains use `example.invalid`, IP
addresses use documentation ranges, and card numbers are payment-network test
values.

Tracked demo assets:

- `samples/support-ticket.txt` shows a support-ticket workflow.
- `samples/incident-log.txt` shows log-style incident data.
- `samples/queries.sql` shows SQL anonymization.
- `samples/passengers.csv` shows CSV anonymization.
- `record.sh` runs a local terminal demo from a fresh checkout.
- `hero.tape` is the VHS source for the generated hero recording.

Generated assets such as `hero.gif`, terminal casts, temporary maps, and
intermediate anonymized files are ignored. Recreate them when needed:

```bash
demo/record.sh
vhs demo/hero.tape
```

Try the samples directly:

```bash
mkdir -p demo/tmp
cargo run --quiet -- -i demo/samples/support-ticket.txt --mapping demo/tmp/demo-map.json
cargo run --quiet -- --format sql -i demo/samples/queries.sql --mapping demo/tmp/demo-map.json
cargo run --quiet -- --format csv -i demo/samples/passengers.csv --mapping demo/tmp/demo-map.json
```
