from __future__ import annotations
"""FastAPI service providing log analysis endpoints."""

from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from .log_processor import analyse_lines
from .utils import save_state, STATE
from .vector_db import VECTOR_DB, embed

app = FastAPI()


class Logs(BaseModel):
    """Schema for a batch of log lines sent to the API."""

    # Raw log lines that should be processed in order
    logs: List[str]


class InvestigateQuery(BaseModel):
    """Payload for the ``/investigate`` endpoint."""

    log: str
    top_k: int = 5


@app.post("/analyze/logs")
async def analyze_logs(payload: Logs):
    """Analyze log lines and return structured analysis results.

    Parameters
    ----------
    payload:
        The :class:`Logs` object containing log lines from a client.

    Returns
    -------
    list[dict]
        A list of analysis results for each selected log line.
    """

    return analyse_lines(payload.logs)


@app.post("/investigate")
async def investigate_log(query: InvestigateQuery):
    """Search similar historical logs for a given log line."""

    vec = embed(query.log)
    ids, dists = VECTOR_DB.search(vec, k=query.top_k)
    cases = VECTOR_DB.get_cases(ids)
    return [
        {"log": c.get("log"), "analysis": c.get("analysis"), "distance": d}
        for c, d in zip(cases, dists)
    ]


@app.on_event("shutdown")
def _shutdown() -> None:
    save_state(STATE)
    VECTOR_DB.save()
