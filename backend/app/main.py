"""PrivAI FastAPI application entrypoint."""

import uuid
from typing import Callable
from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.router import api_router
from backend.app.config import settings
from backend.app.core.exceptions import PayloadTooLargeException, PrivAIException
from backend.app.models.responses import SafeErrorDetail, SafeErrorResponse

from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enforce runtime database isolation before serving traffic."""
    settings.validate_runtime_database_isolation()
    yield


app = FastAPI(
    title="PrivAI Privacy Firewall",
    description="Context-aware privacy firewall for AI applications.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def verify_team_access(request: Request, call_next: Callable) -> Response:
    """Verify team access passkey when TEAM_ACCESS_KEY is configured.

    Protects shared demonstration instances from unauthorized external scraping.
    """
    if settings.TEAM_ACCESS_KEY:
        path = request.url.path
        # Allow static frontend assets, root, health probe, and CORS preflights
        if (
            path == "/health"
            or request.method == "OPTIONS"
            or not path.startswith("/v1")
        ):
            return await call_next(request)

        provided_key = (
            request.headers.get("x-privai-team-key")
            or request.query_params.get("team_key")
        )
        if provided_key != settings.TEAM_ACCESS_KEY:
            request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
            error_response = SafeErrorResponse(
                error=SafeErrorDetail(
                    code="UNAUTHORIZED_TEAM_ACCESS",
                    message="Valid team access passkey required to access this PrivAI demonstration instance.",
                    request_id=request_id,
                )
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=error_response.model_dump(),
                headers={"WWW-Authenticate": "TeamKey"},
            )

    return await call_next(request)


@app.middleware("http")
async def enforce_body_size_limit(request: Request, call_next: Callable) -> Response:
    """Enforce maximum JSON body size (32 KiB) before expensive processing.

    Security Invariant: Prevents resource exhaustion and denial of service.
    """
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.MAX_BODY_SIZE_BYTES:
                error_response = SafeErrorResponse(
                    error=SafeErrorDetail(
                        code="PAYLOAD_TOO_LARGE",
                        message=(
                            f"Request body of {content_length} bytes exceeds maximum allowed "
                            f"size of {settings.MAX_BODY_SIZE_BYTES} bytes."
                        ),
                        request_id=request_id,
                    )
                )
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content=error_response.model_dump(),
                )
        except ValueError:
            error_response = SafeErrorResponse(
                error=SafeErrorDetail(
                    code="INVALID_HEADER",
                    message="Invalid Content-Length header.",
                    request_id=request_id,
                )
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=error_response.model_dump(),
            )

    # For streaming or chunked payloads without Content-Length, read body safely
    body = await request.body()
    if len(body) > settings.MAX_BODY_SIZE_BYTES:
        error_response = SafeErrorResponse(
            error=SafeErrorDetail(
                code="PAYLOAD_TOO_LARGE",
                message=(
                    f"Request payload of {len(body)} bytes exceeds maximum allowed "
                    f"size of {settings.MAX_BODY_SIZE_BYTES} bytes."
                ),
                request_id=request_id,
            )
        )
        return JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content=error_response.model_dump(),
        )

    response = await call_next(request)
    return response


# Register CORSMiddleware outermost so all responses (including errors) receive CORS headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_origin_regex=settings.CORS_ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic/FastAPI validation errors with safe error envelope.

    Security Invariant: Never echoes raw prompt text or matched values.
    """
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    # Create safe error messages without exposing raw user content
    errors = exc.errors()
    safe_error_messages: list[str] = []
    has_large_prompt = False

    for err in errors:
        loc = " -> ".join(str(item) for item in err.get("loc", []))
        msg = err.get("msg", "Validation failed")
        
        # Check if the error is prompt size exceeding limit
        if "exceeds maximum allowed limit" in msg or "10240" in msg:
            has_large_prompt = True

        safe_error_messages.append(f"[{loc}]: {msg}")

    # If prompt exceeded 10 KiB, return 413 per blueprint
    if has_large_prompt:
        error_resp = SafeErrorResponse(
            error=SafeErrorDetail(
                code="PAYLOAD_TOO_LARGE",
                message="Prompt text exceeds the 10 KiB size limit.",
                request_id=request_id,
            )
        )
        return JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content=error_resp.model_dump(),
        )

    error_response = SafeErrorResponse(
        error=SafeErrorDetail(
            code="VALIDATION_ERROR",
            message="; ".join(safe_error_messages),
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_response.model_dump(),
    )


@app.exception_handler(PayloadTooLargeException)
async def payload_too_large_exception_handler(
    request: Request, exc: PayloadTooLargeException
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    error_response = SafeErrorResponse(
        error=SafeErrorDetail(
            code=exc.code,
            message=exc.message,
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
    )


@app.exception_handler(PrivAIException)
async def privai_exception_handler(
    request: Request, exc: PrivAIException
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    error_response = SafeErrorResponse(
        error=SafeErrorDetail(
            code=exc.code,
            message=exc.message,
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
    )


from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

_frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> Response:
    # SPA fallback: For GET requests to non-API paths, serve frontend index.html if built
    if (
        exc.status_code == 404
        and request.method == "GET"
        and not request.url.path.startswith("/v1")
        and not request.url.path.startswith("/health")
    ):
        index_file = _frontend_dist / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))

    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    error_response = SafeErrorResponse(
        error=SafeErrorDetail(
            code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler ensuring fail-closed safety.

    Security Invariant: Never exposes internal stack traces or secrets.
    """
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    error_response = SafeErrorResponse(
        error=SafeErrorDetail(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected error occurred while processing the request.",
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(),
    )


# Root level /health route
app.include_router(health_router)

# Versioned API routes under /v1
app.include_router(api_router, prefix="/v1")

# Mount production frontend build if present (Unified Single-Origin Deployment)
if _frontend_dist.exists() and (_frontend_dist / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")

