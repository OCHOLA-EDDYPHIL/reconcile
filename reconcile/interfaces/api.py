"""FastAPI process shell."""

import uvicorn
from fastapi import FastAPI

from reconcile import __version__

app = FastAPI(title="RECONCILE", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    """Return local process health without provider access."""

    return {"status": "ok"}


def main() -> None:
    """Run the local API shell."""

    uvicorn.run(app, host="127.0.0.1", port=8000)
