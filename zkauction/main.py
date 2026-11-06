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
from starlette.exceptions import HTTPException as StarletteHTTPException  # noqa: E402

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
        msg = "; ".join("%s: %s" % (".".join(str(p) for p in e["loc"]), e["msg"]) for e in errors[:3])
        return _error(422, "VALIDATION_ERROR", msg or "request failed schema validation", errors=errors)

    @app.exception_handler(StarletteHTTPException)
    def _http(_: Request, exc: StarletteHTTPException):
        # 404 unknown route, 405 wrong method, 400 unparsable body: same envelope as domain errors.
        codes = {400: "BAD_REQUEST", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        return _error(exc.status_code, codes.get(exc.status_code, "HTTP_ERROR"), str(exc.detail))

    @app.middleware("http")
    async def _stamp_and_csp(request: Request, call_next):
        # Stamp arrival time on the event loop, before the request waits for a worker thread,
        # so the bid deadline is judged by when the bid reached the server.
        request.state.received_at = request.app.state.clock.now()
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
