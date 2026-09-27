"""Service entrypoint: run with ``uvicorn main:app``."""
from csp_service.app import create_app

app = create_app()
