import json
import os
from pathlib import Path
from pydantic import ValidationError
from rich.console import Console

from schemas.models import StandardizedLog

console = Console()


def ingest_logs(raw_log_list: list[dict]) -> tuple[list[StandardizedLog], list[dict]]:
    valid_logs: list[StandardizedLog] = []
    corrupted: list[dict] = []

    for entry in raw_log_list:
        try:
            log = StandardizedLog(
                log_type=entry["log_type"],
                resource_id=entry["resource_id"],
                resource_type=entry["resource_type"],
                event_time=entry["event_time"],
                payload=entry.get("payload", {}),
                region=entry.get("region", "unknown"),
            )
            valid_logs.append(log)
        except (ValidationError, KeyError, TypeError) as exc:
            corrupted.append({"original": entry, "error": str(exc)})

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    if corrupted:
        with open(output_dir / "corrupted_logs.jsonl", "w") as f:
            for c in corrupted:
                f.write(json.dumps(c, default=str) + "\n")

    console.print(
        f"[bold]Processed {len(raw_log_list)} logs.[/bold] "
        f"[green]{len(valid_logs)} succeeded.[/green] "
        f"[red]{len(corrupted)} corrupted (see output/corrupted_logs.jsonl).[/red]"
    )
    return valid_logs, corrupted
