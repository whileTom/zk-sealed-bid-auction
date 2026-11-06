"""App factory.

Run:  python -m uvicorn zkauction.main:app --port 8000
Then: http://localhost:8000/docs (API) and http://localhost:8000/ui/ (frontend)
"""
import mimetypes
from pathlib import Path

# Some Windows machines map .js to text/plain in the registry; browsers then refuse ES modules.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/javascript", ".mjs")

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.responses import JSONResponse, RedirectResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

from .api import router  # noqa: E402
from .clock import SystemClock  # noqa: E402
from .crypto.errors import InvalidProof  # noqa: E402
from .errors import DomainError  # noqa: E402
from .store import Store  # noqa: E402

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"


def _error(status: int, code: str, message: str, **extra) -> JSONResponse:
    # Never echo request bodies (they may contain a bid value or randomness).
    return JSONResponse(status_code=status, content={"detail": {"code": code, "message": message, **extra}})


def create_app(clock=None, store=None) -> FastAPI:
    app = FastAPI(title="zk-sealed-bid-auction",
                  description="Sealed-bid auctions with Pedersen commitments and ZK range proofs.")
    app.state.store = store or Store()
    app.state.clock = clock or SystemClock()

    @app.exception_handler(DomainError)
    def _domain(_: Request, exc: DomainError):
        return _error(exc.status, exc.code, exc.message)

    @app.exception_handler(InvalidProof)
    def _proof(_: Request, exc: InvalidProof):
        return _error(400, exc.code, str(exc))

    @app.exception_handler(RequestValidationError)
    def _validation(_: Request, exc: RequestValidationError):
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg")} for e in exc.errors()]
        return _error(422, "VALIDATION_ERROR", "request failed schema validation", errors=errors)

    @app.middleware("http")
    async def _csp(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/ui"):
            response.headers["Content-Security-Policy"] = CSP
        return response

    app.include_router(router)

    @app.get("/", include_in_schema=False)
    def _root():
        return RedirectResponse("/ui/")

    if FRONTEND.is_dir():
        app.mount("/ui", StaticFiles(directory=FRONTEND, html=True), name="ui")
    return app


app = create_app()
