"""
Database connection management for RedOPS.

Provides session management and connection pooling.
"""

from typing import Optional, Generator
from contextlib import contextmanager
import os
import logging

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool

from .models import Base

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """Database configuration."""

    def __init__(
        self,
        url: Optional[str] = None,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: int = 30,
        pool_recycle: int = 1800,
        echo: bool = False,
    ):
        """
        Initialize database configuration.

        Args:
            url: Database URL (defaults to DATABASE_URL env var)
            pool_size: Connection pool size
            max_overflow: Max connections above pool_size
            pool_timeout: Timeout waiting for connection
            pool_recycle: Recycle connections after seconds
            echo: Echo SQL statements
        """
        self.url = url or os.environ.get(
            "DATABASE_URL",
            "postgresql://redops:redops@localhost:5432/redops"
        )
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.echo = echo or os.environ.get("DATABASE_ECHO", "false").lower() == "true"

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Create config from environment variables."""
        return cls(
            url=os.environ.get("DATABASE_URL"),
            pool_size=int(os.environ.get("DATABASE_POOL_SIZE", "5")),
            max_overflow=int(os.environ.get("DATABASE_MAX_OVERFLOW", "10")),
            pool_timeout=int(os.environ.get("DATABASE_POOL_TIMEOUT", "30")),
            pool_recycle=int(os.environ.get("DATABASE_POOL_RECYCLE", "1800")),
            echo=os.environ.get("DATABASE_ECHO", "false").lower() == "true",
        )


class Database:
    """
    Database connection manager.

    Handles engine creation, session management, and connection pooling.
    """

    def __init__(self, config: Optional[DatabaseConfig] = None):
        """
        Initialize database manager.

        Args:
            config: Database configuration
        """
        self.config = config or DatabaseConfig.from_env()
        self._engine = None
        self._session_factory = None

    @property
    def engine(self):
        """Get or create the database engine."""
        if self._engine is None:
            self._engine = create_engine(
                self.config.url,
                poolclass=QueuePool,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                echo=self.config.echo,
            )

            # Add event listeners for connection debugging
            @event.listens_for(self._engine, "connect")
            def on_connect(dbapi_conn, connection_record):
                logger.debug("Database connection established")

            @event.listens_for(self._engine, "checkout")
            def on_checkout(dbapi_conn, connection_record, connection_proxy):
                logger.debug("Connection checked out from pool")

        return self._engine

    @property
    def session_factory(self) -> sessionmaker:
        """Get or create the session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine,
                autocommit=False,
                autoflush=False,
                expire_on_commit=False,
            )
        return self._session_factory

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.session_factory()

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope around a series of operations.

        Yields:
            Database session

        Example:
            with db.session_scope() as session:
                session.add(user)
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def create_tables(self) -> None:
        """Create all tables defined in models."""
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created")

    def drop_tables(self) -> None:
        """Drop all tables (use with caution!)."""
        Base.metadata.drop_all(self.engine)
        logger.warning("Database tables dropped")

    def check_connection(self) -> bool:
        """Check if database connection is working."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False

    def dispose(self) -> None:
        """Dispose of the connection pool."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database connection pool disposed")


# Global database instance
_database: Optional[Database] = None


def get_database() -> Database:
    """Get the global database instance."""
    global _database
    if _database is None:
        _database = Database()
    return _database


def get_session() -> Session:
    """Get a database session from the global instance."""
    return get_database().get_session()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Get a session scope from the global instance."""
    with get_database().session_scope() as session:
        yield session


def init_database(config: Optional[DatabaseConfig] = None) -> Database:
    """
    Initialize the global database instance.

    Args:
        config: Database configuration

    Returns:
        Database instance
    """
    global _database
    _database = Database(config)
    return _database
