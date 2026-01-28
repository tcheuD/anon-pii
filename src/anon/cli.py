"""CLI interface for anon."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from anon import __version__
from anon.core.analyzer import create_analyzer, get_supported_entities
from anon.core.anonymizer import Anonymizer, DetectedEntity
from anon.core.mapping import AnonymizationMapping
from anon.formats.detector import detect_format, Format
from anon.formats.json_handler import process_json
from anon.formats.text_handler import process_text

app = typer.Typer(
    name="anon",
    help="Anonymize PII in debug data for safe sharing with AI tools.",
    no_args_is_help=False,
    add_completion=False,
)
console = Console(stderr=True)


def version_callback(value: bool) -> None:
    if value:
        print(f"anon {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    input_file: Optional[Path] = typer.Option(
        None, "-i", "--input",
        help="Input file (reads from stdin if not provided)",
    ),
    output_file: Optional[Path] = typer.Option(
        None, "-o", "--output",
        help="Output file (writes to stdout if not provided)",
    ),
    format: Optional[Format] = typer.Option(
        None, "-f", "--format",
        help="Input format (auto-detected if not specified)",
    ),
    mapping_file: Optional[Path] = typer.Option(
        None, "-m", "--mapping",
        help="Write mapping to this file",
    ),
    mapping_stderr: bool = typer.Option(
        False, "--mapping-stderr",
        help="Output mapping to stderr",
    ),
    include_mapping: bool = typer.Option(
        False, "--include-mapping",
        help="Include mapping as JSON comment in output",
    ),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Show detected entities on stderr",
    ),
    language: str = typer.Option(
        "en", "-l", "--language",
        help="Language for NLP detection (en, fr)",
    ),
    score_threshold: float = typer.Option(
        0.5, "--threshold",
        help="Minimum confidence score for detection (0.0-1.0)",
    ),
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """Anonymize PII in debug data for safe sharing with AI tools."""
    if ctx.invoked_subcommand is not None:
        return

    if input_file:
        if not input_file.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)
        content = input_file.read_text()
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    else:
        console.print("[yellow]No input provided. Use --help for usage.[/yellow]")
        raise typer.Exit(1)

    if not content.strip():
        print(content, end="")
        raise typer.Exit(0)

    detected_format = format or detect_format(content)

    analyzer = create_analyzer(use_nlp=False)
    anonymizer = Anonymizer(analyzer)

    all_detected: list[DetectedEntity] = []

    def anonymize_fn(text: str) -> str:
        anonymized, detected = anonymizer.anonymize(
            text, language=language, score_threshold=score_threshold
        )
        all_detected.extend(detected)
        return anonymized

    if detected_format == Format.JSON:
        try:
            result = process_json(content, anonymize_fn)
        except Exception:
            result = process_text(content, anonymize_fn)
    else:
        result = process_text(content, anonymize_fn)

    if include_mapping:
        mapping_json = anonymizer.get_mapping().to_json()
        result = f"{result}\n\n/* MAPPING:\n{mapping_json}\n*/"

    if output_file:
        output_file.write_text(result)
    else:
        print(result, end="" if result.endswith("\n") else "\n")

    mapping = anonymizer.get_mapping()

    if mapping_file:
        mapping.save(mapping_file)
        if verbose:
            console.print(f"[dim]Mapping saved to {mapping_file}[/dim]")

    if mapping_stderr:
        console.print(mapping.to_json())

    if verbose and all_detected:
        _print_detected_entities(all_detected)


def _print_detected_entities(entities: list[DetectedEntity]) -> None:
    """Print detected entities table to stderr."""
    table = Table(title="Detected Entities", show_header=True, header_style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Original")
    table.add_column("Token", style="green")
    table.add_column("Score", justify="right")

    seen: set[str] = set()
    for entity in entities:
        key = f"{entity.entity_type}:{entity.text}"
        if key not in seen:
            seen.add(key)
            table.add_row(
                entity.entity_type,
                entity.text[:40] + "..." if len(entity.text) > 40 else entity.text,
                entity.token or "",
                f"{entity.score:.2f}",
            )

    console.print(table)


@app.command()
def restore(
    input_file: Optional[Path] = typer.Argument(
        None,
        help="Input file with anonymized data (reads from stdin if not provided)",
    ),
    mapping_file: Path = typer.Option(
        ..., "-m", "--mapping",
        help="Mapping file to use for restoration",
    ),
    output_file: Optional[Path] = typer.Option(
        None, "-o", "--output",
        help="Output file (writes to stdout if not provided)",
    ),
) -> None:
    """Restore original values from anonymized data using a mapping file."""
    if input_file:
        if not input_file.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)
        content = input_file.read_text()
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    else:
        console.print("[red]No input provided.[/red]")
        raise typer.Exit(1)

    if not mapping_file.exists():
        console.print(f"[red]Mapping file not found: {mapping_file}[/red]")
        raise typer.Exit(1)

    mapping = AnonymizationMapping.load(mapping_file)
    result = mapping.restore_text(content)

    if output_file:
        output_file.write_text(result)
    else:
        print(result, end="" if result.endswith("\n") else "\n")

    console.print(f"[dim]Restored {len(mapping)} entities[/dim]")


@app.command("list-entities")
def list_entities() -> None:
    """List all supported entity types."""
    analyzer = create_analyzer(use_nlp=False)
    entities = get_supported_entities(analyzer)

    table = Table(title="Supported Entity Types", show_header=True)
    table.add_column("Entity Type", style="cyan")

    custom_entities = {
        "FR_PHONE_NUMBER", "FR_IBAN", "FR_SSN", "FR_PASSPORT",
        "AIRCRAFT_REGISTRATION", "FLIGHT_NUMBER", "CREW_CODE",
    }

    for entity in entities:
        style = "green" if entity in custom_entities else None
        table.add_row(entity, style=style)

    console.print(table)
    console.print(f"\n[dim]Total: {len(entities)} entities[/dim]")
    console.print("[green]Green[/green] = Custom recognizers (French + Aviation)")


if __name__ == "__main__":
    app()
