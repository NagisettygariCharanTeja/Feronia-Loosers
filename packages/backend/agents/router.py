import os
from typing import Literal

from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from rich.console import Console

console = Console()

ROUTER_SYSTEM_PROMPT = """You are a cloud infrastructure triage agent for a construction technology company (Hilti).
Given a summary of ingested AWS logs and graph statistics, classify the batch into one or
both of: ["secops", "greenops"].

"secops" if ANY log suggests: open ports, IAM policy changes, public exposure,
failed auth, unencrypted data, or security group modifications.

"greenops" if ANY log suggests: high-cost instance types, low CPU utilisation,
unattached volumes, zombie resources, or high-carbon regions.

Return BOTH if the batch contains cross-cutting signals (common for real infrastructure).

Output ONLY a JSON object: {"labels": ["secops", "greenops"]}"""


class RouterOutput(BaseModel):
    labels: list[Literal["secops", "greenops"]]


def route_logs(log_summary: str, graph_summary: str) -> list[str]:
    try:
        llm = ChatOpenAI(
            model=os.environ.get("GRAFILAB_MODEL", "gemini/gemini-3.1-flash-lite-preview"),
            temperature=0,
            openai_api_key=os.environ["GRAFILAB_API_KEY"],
            openai_api_base=os.environ.get(
                "GRAFILAB_BASE_URL",
                "https://console-api.grafilab.ai/api/oai/v1/models",
            ),
        )
        structured_llm = llm.with_structured_output(RouterOutput)
        user_msg = f"## Log Summary\n{log_summary}\n\n## Graph Summary\n{graph_summary}"
        result = structured_llm.invoke(
            [
                {"role": "system", "content": ROUTER_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
        )
        console.print(f"[cyan]Router decided:[/cyan] {result.labels}")
        return result.labels
    except Exception as exc:
        console.print(f"[red]Router LLM call failed: {exc}. Defaulting to both agents.[/red]")
        return ["secops", "greenops"]
