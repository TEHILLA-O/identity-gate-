import asyncio
import logging
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api
from app.config import get_settings
from app.db import Base, engine
from app.keycloak.errors import IntegrationError
from app.security.logging import install

install()
logger = logging.getLogger("identitygate")


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from app import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        stop = asyncio.Event()
        task = None
        if settings.worker_enabled:
            task = asyncio.create_task(_worker(stop))
        yield
        stop.set()
        if task:
            task.cancel()

    app = FastAPI(title="IdentityGate", version="1.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.public_app_url, "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        correlation_id = request.headers.get("x-correlation-id") or str(uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    @app.exception_handler(IntegrationError)
    async def integration_error(request: Request, exc: IntegrationError):
        return JSONResponse(
            status_code=exc.status or 409,
            content={"error": {"code": "integration", "message": str(exc), "workflow_id": getattr(exc, "workflow_id", None), "correlation_id": getattr(request.state, "correlation_id", None)}},
        )

    app.include_router(api, prefix="/api/v1")
    return app


async def _worker(stop: asyncio.Event) -> None:
    from app.services.worker import tick

    settings = get_settings()
    while not stop.is_set():
        try:
            await asyncio.to_thread(tick)
        except Exception:
            logger.exception("background worker failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.worker_interval_seconds)
        except TimeoutError:
            continue


app = create_app()
