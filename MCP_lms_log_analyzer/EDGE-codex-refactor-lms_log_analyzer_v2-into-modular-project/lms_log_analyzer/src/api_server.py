from __future__ import annotations
"""FastAPI service providing log analysis endpoints."""

from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from .log_processor import analyse_lines
from .utils import save_state, STATE
from .vector_db import VECTOR_DB

app = FastAPI()


class Logs(BaseModel):
    """Schema for a batch of log lines sent to the API."""

    # Raw log lines that should be processed in order
    logs: List[str]


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


@app.on_event("shutdown")
def _shutdown() -> None:
    save_state(STATE)
    VECTOR_DB.save()
