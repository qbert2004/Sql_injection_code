"""Request adapters for different frameworks."""

from sql_injection_protector.layers.request.adapters.base import (
    BaseAdapter,
    MiddlewareBase,
)
from sql_injection_protector.layers.request.adapters.fastapi import (
    SQLIProtectorMiddleware as FastAPIMiddleware,
    create_middleware as create_fastapi_middleware,
)
from sql_injection_protector.layers.request.adapters.wsgi import (
    WSGIProtector,
    wrap_wsgi,
)
from sql_injection_protector.layers.request.adapters.asgi import (
    ASGIProtector,
    wrap_asgi,
)

# Django imports are optional (may not have Django installed)
try:
    from sql_injection_protector.layers.request.adapters.django import (
        SQLIProtectorMiddleware as DjangoMiddleware,
        AsyncSQLIProtectorMiddleware as AsyncDjangoMiddleware,
    )
except ImportError:
    DjangoMiddleware = None
    AsyncDjangoMiddleware = None

__all__ = [
    "BaseAdapter",
    "MiddlewareBase",
    "FastAPIMiddleware",
    "create_fastapi_middleware",
    "DjangoMiddleware",
    "AsyncDjangoMiddleware",
    "WSGIProtector",
    "wrap_wsgi",
    "ASGIProtector",
    "wrap_asgi",
]
