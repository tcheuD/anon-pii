# Prepare a support ticket for AI debugging

Use the [browser ticket workspace](https://tcheud.github.io/anon-pii/#try) to
prepare ticket text locally, copy recognized values as tokens to your chosen AI tool, and restore
those values in its reply. No CLI installation or anon-pii account is needed.
Keep the same tab open until you finish restoring the reply.

## Try the browser workflow locally

1. Choose **Load fictional example**, then **Prepare ticket**.
2. Inspect the prepared text. Detected values appear as bracketed tokens such
   as `[EMAIL_ADDRESS_a1b2c3d4]`; surrounding incident details remain readable.
   Review the whole ticket for values that were missed or redacted incorrectly.
3. Choose **Copy tokenized ticket**. For a local trial, paste it into the reply
   field in the same workspace instead of opening an AI tool.
4. Choose **Restore reply**. Known tokens become their original values again.
   This local trial requires no AI request.
5. Choose **Clear session** when finished. You can bookmark the workspace and
   start a new session for your next ticket.

For a real handoff, paste only the reviewed tokenized text into your chosen AI
tool and ask it to preserve bracketed tokens exactly. Copy its response back
into the workspace's reply field, choose **Restore reply**, and inspect the
result. The status counts restored token occurrences, including repeats, and
flags unrecognized placeholders with the usual token shape (an uppercase type
and eight lowercase hexadecimal digits in brackets). Old-session tokens can
therefore produce a zero-restoration result. Changed or incomplete tokens may
not be recognized by this notice; always inspect the reply. Plain text without
tokens stays unchanged and can still be copied.

**Copy restored reply** copies the result, which can contain original values; use it
only in the destination where those values belong.

If the browser blocks clipboard access, select and copy the prepared text
manually. Do not copy the source ticket by mistake.

The workspace does not contact your AI provider or send the ticket for you.
The external tool receives whatever you paste into it, including any sensitive
values that detection missed and anything you add to your prompt.

## Review and session boundaries

Browser name detection uses local heuristics. It is enabled in the browser
build, is not an ML model, and can miss names or mistake ordinary words for
names. Postal-address support covers selected French forms, not every address
or country. Inspect names, addresses, credentials, and organization-specific
identifiers yourself. Detection counts do not prove that a ticket is anonymous.

The browser works with ticket text; use the CLI's format-aware paths when you
need JSON-value, CSV-field, or SQL-literal processing. Do not infer document,
image, or attachment redaction from what happens in the text workspace.

| Action | What happens to the prepared ticket and mapping |
|--------|-----------------------------------------------|
| Copy tokenized ticket or restore a reply | The current prepared mapping remains available in this tab |
| Edit the source ticket | Prepared output and replies are cleared; prepare the edited ticket before copying again |
| Prepare ticket again | A fresh mapping replaces the previous one and clears the old reply |
| Load another example | The old session is discarded; prepare the new source before copying |
| Clear session | Source, prepared output, reply, restored output, and the page's mapping are cleared |
| Reload or close the page | The mapping is lost; saved tokens cannot be restored in a new session |

The workspace does not save your ticket or mapping to an account or browser
storage. Keep the tab and its source unchanged while waiting for a response.
Unknown, altered, or old-session tokens remain unchanged; inspect any tokens
left in the restored response. If the session is lost, start a new handoff from
the original ticket rather than expecting old tokens to restore.

Clearing the page does not clear your clipboard, clipboard history, or anything
already pasted into another application. A restored reply intentionally
contains original values. Browser extensions and other local software retain
their usual access; this workflow is not a sandbox.

## Use the CLI for a repeatable command

[Install the CLI](../README.md#installation). Release binaries include
heuristic name detection; enable it with `--ner`. For a source build, include
`--features ner-lite`. The following commands use the fictional French ticket
and local reply script from a repository checkout; the reply script needs Python 3:

```bash
# Inspect the fictional ticket before handing it off.
anon-pii --ner run --dry-run < demo/samples/support-ticket-fr.txt

# See what the child receives, then read its simulated response with values restored.
anon-pii --ner run -- python3 demo/ticket-reply.py < demo/samples/support-ticket-fr.txt
```

The local reply script prints its received tokenized input to stderr and writes
its simulated response to stdout. anon-pii restores known tokens in stdout, so
you can compare the child's input with the response in your terminal. This is a
fictional demonstration; it calls no AI tool or network service and saves no
mapping. A minimal echo-only proof is `anon-pii --ner run -- cat < ticket.txt`.

For an installed and configured AI command, use the same detection settings:

```bash
anon-pii --ner run -- claude -p "Explain the failure; preserve bracketed tokens exactly." < ticket.txt
```

Replace the child command with the tool you use. Inspect the preview before
handoff. For organization-specific identifiers, add a reviewed custom
recognizer using `--config` in both commands; see the
[configuration example](../testdata/custom-recognizers.yaml). Keep the same
flags and configuration for later tickets with the same format.

CLI preview and execution are separate invocations with fresh tokens; a preview
is not a saved transaction. `run` keeps its mapping in memory, transforms child
stdin, and restores known tokens in stdout. Child stderr passes through
unchanged, and the child retains its normal filesystem and network access.
See the [run contract](../README.md#run-contract-and-limitations) and the
[runnable demos](../demo/README.md).

For SQL excerpts, use `anon-pii --format sql run --dry-run < ticket.sql` and
keep `--format sql` when running the child command. In v0.3.3 and current source builds,
default token preparation decodes PostgreSQL `E'...'` named control escapes
(`\b`, `\f`, `\n`, `\r`, `\t`) for detection, including wrapped emails such as
`E'ada@\r\n\texample.com'`. Restoration preserves the original escape spelling.
Ordinary quoted strings and dollar-quoted strings retain literal backslashes.
This is not a full SQL escape parser; other replacement operators are unchanged.
Older v0.3.2 archives do not include wrapped-email or E-string control-escape support.

## Optional outcome note

To evaluate whether the workflow helps you, keep a local note after the first
use and again after a later ticket. No usage report is sent automatically.
Record only:

- product version or revision, browser/OS or CLI platform, and detection settings;
- first use or repeat use;
- completed or blocked; and
- blocker category: setup, missed value, over-redaction, changed token, lost
  session, or another short description without ticket content.

You may voluntarily share that outcome through the repository's
[discussion](https://github.com/tcheuD/anon-pii/discussions) or
[workflow feedback form](https://github.com/tcheuD/anon-pii/issues/new?template=ticket_feedback.yml).
Use fictional reproductions for detector reports and the
[private security-reporting path](../SECURITY.md) for vulnerabilities. Do not
include real tickets, personal data, prompts, mapping files, or sensitive
command output. Completing the local example is a functional check, not a
measurement of adoption or detector accuracy on your own data.
