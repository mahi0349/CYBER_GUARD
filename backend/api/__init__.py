from .account import router as account_router
from .deepfake import router as deepfake_router
from .events import router as events_router
from .health import router as health_router
from .phishing import router as phishing_router

__all__ = ["health_router", "events_router", "phishing_router", "deepfake_router", "account_router"]
