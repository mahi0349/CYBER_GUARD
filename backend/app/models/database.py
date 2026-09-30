import logging
import socket
import re
from typing import Dict, Any, Tuple
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("cyberguard.database")

configured_db_url = settings.DATABASE_URL
active_db_url = configured_db_url
fallback_active = False

connect_args = {}
if active_db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
elif active_db_url.startswith("postgresql"):
    connect_args = {"connect_timeout": 3}

try:
    engine = create_engine(active_db_url, connect_args=connect_args)
    with engine.connect() as conn:
        pass
    logger.info(f"Database successfully connected using: {engine.dialect.name}")
except Exception as e:
    logger.warning(f"Could not connect to configured database ({active_db_url}): {e}. Falling back to local SQLite.")
    active_db_url = "sqlite:///./cyberguard.db"
    connect_args = {"check_same_thread": False}
    engine = create_engine(active_db_url, connect_args=connect_args)
    fallback_active = True

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    logger.warning(f"Initial create_all failed: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def is_postgres_port_open(host: str = "localhost", port: int = 5432) -> bool:
    """Fast check if PostgreSQL port is open and listening."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6)
            res = sock.connect_ex((host, port))
            return res == 0
    except Exception:
        return False

def mask_connection_url(url: str) -> str:
    """Sanitize passwords in connection strings."""
    return re.sub(r":([^:@]+)@", r":***@", url)

def get_database_status(db=None) -> Dict[str, Any]:
    """Return real-time diagnostic status of the database and container."""
    from app.models.threat import Threat, Scan
    from app.models.incident import Incident
    from app.models.user import User

    active_driver = engine.dialect.name
    is_postgres = active_driver == "postgresql"
    postgres_running = is_postgres_port_open()

    counts = {"threats": 0, "incidents": 0, "scans": 0, "users": 0}

    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        counts["threats"] = db.query(Threat).count()
        counts["incidents"] = db.query(Incident).count()
        counts["scans"] = db.query(Scan).count()
        counts["users"] = db.query(User).count()
    except Exception as e:
        logger.warning(f"Error querying table counts: {e}")
    finally:
        if close_db:
            db.close()

    return {
        "configured_driver": "postgresql" if "postgres" in configured_db_url else "sqlite",
        "active_driver": active_driver,
        "active_url": mask_connection_url(active_db_url),
        "status": "online",
        "is_postgres": is_postgres,
        "postgres_container_running": postgres_running,
        "fallback_in_use": fallback_active or (not is_postgres and "postgres" in configured_db_url),
        "counts": counts
    }

def try_connect_postgres(
    target_url: str = "postgresql://cyberguard:cyberguard_secure_password@localhost:5432/cyberguard"
) -> Tuple[bool, str]:
    """Attempt dynamic switch / connection to PostgreSQL."""
    global engine, SessionLocal, active_db_url, fallback_active

    if not is_postgres_port_open():
        return False, "PostgreSQL port 5432 is not reachable. Ensure Docker Desktop is running and execute: docker compose up -d"

    try:
        new_engine = create_engine(target_url, connect_args={"connect_timeout": 3})
        with new_engine.connect() as conn:
            pass
        # Connection succeeded, migrate schemas
        Base.metadata.create_all(bind=new_engine)

        engine = new_engine
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        active_db_url = target_url
        fallback_active = False
        return True, "Successfully connected to Docker PostgreSQL container (cyberguard_db) and verified tables."
    except Exception as e:
        return False, f"Connection failed: {str(e)}"
