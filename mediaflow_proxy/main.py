import asyncio
import logging
import re
from importlib import resources

from fastapi import FastAPI, Depends, Security, HTTPException
from fastapi.security import APIKeyQuery, APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles

from mediaflow_proxy.configs import settings
from mediaflow_proxy.middleware import UIAccessControlMiddleware
from mediaflow_proxy.routes import proxy_router, extractor_router, speedtest_router
from mediaflow_proxy.schemas import GenerateUrlRequest, GenerateMultiUrlRequest, MultiUrlRequestItem
from mediaflow_proxy.utils.crypto_utils import EncryptionHandler, EncryptionMiddleware
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url

logging.basicConfig(level=settings.log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# --- Middleware to normalize double slashes in path ---
class NormalizePathMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        scope = dict(request.scope)  # shallow copy
        original_path = scope["path"]
        normalized_path = re.sub(r"/{2,}", "/", original_path)
        if original_path != normalized_path:
            scope["path"] = normalized_path
            request = Request(scope, request.receive)
        return await call_next(request)
# -------------------------------------------------------

app = FastAPI()

# Add NormalizePathMiddleware first
app.add_middleware(NormalizePathMiddleware)

# Optional: Redirect double slashes instead of rewriting (commented out)

@app.middleware("http")
async def redirect_double_slash(request: Request, call_next):
    path = request.url.path
    if "//" in path:
        new_path = re.sub(r"/{2,}", "/", path)
        new_url = str(request.url).replace(path, new_path)
        return RedirectResponse(new_url, status_code=307)
    return await call_next(request)


# Debugging middleware to log incoming paths
@app.middleware("http")
async def log_path(request: Request, call_next):
    print(f"Incoming path: {request.url.path}")
    response = await call_next(request)
    return response

api_password_query = APIKeyQuery(name="api_password", auto_error=False)
api_password_header = APIKeyHeader(name="api_password", auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(EncryptionMiddleware)
app.add_middleware(UIAccessControlMiddleware)


async def verify_api_key(api_key: str = Security(api_password_query), api_key_alt: str = Security(api_password_header)):
    if not settings.api_password:
        return
    if api_key == settings.api_password or api_key_alt == settings.api_password:
        return
    raise HTTPException(status_code=403, detail="Could not validate credentials")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/favicon.ico")
async def get_favicon():
    return RedirectResponse(url="/logo.png")


@app.get("/speedtest")
async def show_speedtest_page():
    return RedirectResponse(url="/speedtest.html")


@app.post(
    "/generate_encrypted_or_encoded_url",
    description="Generate a single encoded URL",
    response_description="Returns a single encoded URL",
    deprecated=True,
    tags=["url"],
)
async def generate_encrypted_or_encoded_url(
    request: GenerateUrlRequest,
):
    return {"encoded_url": (await generate_url(request))["url"]}


@app.post(
    "/generate_url",
    description="Generate a single encoded URL",
    response_description="Returns a single encoded URL",
    tags=["url"],
)
async def generate_url(request: GenerateUrlRequest):
    encryption_handler = EncryptionHandler(request.api_password) if request.api_password else None

    query_params = request.query_params.copy()
    if "api_password" not in query_params and request.api_password:
        query_params["api_password"] = request.api_password

    ip_str = str(request.ip) if request.ip else None

    encoded_url = encode_mediaflow_proxy_url(
        mediaflow_proxy_url=request.mediaflow_proxy_url,
        endpoint=request.endpoint,
        destination_url=request.destination_url,
        query_params=query_params,
        request_headers=request.request_headers,
        response_headers=request.response_headers,
        encryption_handler=encryption_handler,
        expiration=request.expiration,
        ip=ip_str,
        filename=request.filename,
    )

    return {"url": encoded_url}


@app.post(
    "/generate_urls",
    description="Generate multiple encoded URLs with shared common parameters",
    response_description="Returns a list of encoded URLs",
    tags=["url"],
)
async def generate_urls(request: GenerateMultiUrlRequest):
    encryption_handler = EncryptionHandler(request.api_password) if request.api_password else None
    ip_str = str(request.ip) if request.ip else None

    async def _process_url_item(url_item: MultiUrlRequestItem) -> str:
        query_params = url_item.query_params.copy()
        if "api_password" not in query_params and request.api_password:
            query_params["api_password"] = request.api_password

        return encode_mediaflow_proxy_url(
            mediaflow_proxy_url=request.mediaflow_proxy_url,
            endpoint=url_item.endpoint,
            destination_url=url_item.destination_url,
            query_params=query_params,
            request_headers=url_item.request_headers,
            response_headers=url_item.response_headers,
            encryption_handler=encryption_handler,
            expiration=request.expiration,
            ip=ip_str,
            filename=url_item.filename,
        )

    tasks = [_process_url_item(url_item) for url_item in request.urls]
    encoded_urls = await asyncio.gather(*tasks)
    return {"urls": encoded_urls}


# Include routers
app.include_router(proxy_router, prefix="/proxy", tags=["proxy"], dependencies=[Depends(verify_api_key)])
app.include_router(extractor_router, prefix="/extractor", tags=["extractors"], dependencies=[Depends(verify_api_key)])
app.include_router(speedtest_router, prefix="/speedtest", tags=["speedtest"], dependencies=[Depends(verify_api_key)])

# Mount static assets
static_path = resources.files("mediaflow_proxy").joinpath("static")
app.mount("/", StaticFiles(directory=str(static_path), html=True), name="static")


def run():
    import uvicorn
    print("Registered routes:")
    for r in app.routes:
        print(r.path)
    uvicorn.run(app, host="0.0.0.0", port=8888, log_level="info", workers=3)


if __name__ == "__main__":
    run()

from fastapi.responses import RedirectResponse
import re

@app.middleware("http")
async def force_fix_double_slash_path(request: Request, call_next):
    raw_path = request.scope["path"]

    if raw_path.startswith("//proxy"):
        # Rewrite path to /proxy
        fixed_path = re.sub(r"^/+", "/", raw_path)
        fixed_url = str(request.url).replace(raw_path, fixed_path)
        print(f"Redirecting {raw_path} → {fixed_path}")
        return RedirectResponse(url=fixed_url, status_code=307)

    return await call_next(request)
