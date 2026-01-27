"""
Безопасный Database Layer с полной параметризацией запросов
Поддержка SQLAlchemy, asyncpg, psycopg2
"""

from typing import List, Dict, Any, Optional, Union
from contextlib import asynccontextmanager, contextmanager
import logging
from dataclasses import dataclass
from enum import Enum

# SQLAlchemy
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Async PostgreSQL
import asyncpg

logger = logging.getLogger("SafeDatabaseLayer")


# ============================================================================
# БЕЗОПАСНЫЕ QUERY BUILDERS
# ============================================================================

class QueryType(Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


@dataclass
class SafeQuery:
    """Безопасный SQL-запрос с параметризацией"""
    query_type: QueryType
    table: str
    columns: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    values: Optional[Dict[str, Any]] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    order_by: Optional[List[str]] = None


class SafeQueryBuilder:
    """
    Builder для создания безопасных параметризованных запросов
    КРИТИЧНО: Все пользовательские данные передаются как параметры, НЕ в строке запроса
    """
    
    @staticmethod
    def select(
        table: str,
        columns: List[str] = None,
        conditions: Dict[str, Any] = None,
        limit: int = None,
        offset: int = None,
        order_by: List[str] = None
    ) -> tuple[str, Dict[str, Any]]:
        """
        Безопасный SELECT запрос
        
        Example:
            query, params = SafeQueryBuilder.select(
                table="users",
                columns=["id", "username", "email"],
                conditions={"status": "active", "age": 25},
                limit=10
            )
        """
        columns_str = ", ".join(columns) if columns else "*"
        query_parts = [f"SELECT {columns_str} FROM {table}"]
        params = {}
        
        # WHERE условия
        if conditions:
            where_clauses = []
            for i, (key, value) in enumerate(conditions.items()):
                param_name = f"param_{i}"
                where_clauses.append(f"{key} = :{param_name}")
                params[param_name] = value
            
            query_parts.append(f"WHERE {' AND '.join(where_clauses)}")
        
        # ORDER BY
        if order_by:
            # Whitelist для ORDER BY (защита от инъекций в column names)
            safe_order = [col for col in order_by if col.replace('_', '').isalnum()]
            if safe_order:
                query_parts.append(f"ORDER BY {', '.join(safe_order)}")
        
        # LIMIT/OFFSET
        if limit:
            query_parts.append("LIMIT :limit")
            params['limit'] = limit
        
        if offset:
            query_parts.append("OFFSET :offset")
            params['offset'] = offset
        
        query = " ".join(query_parts)
        return query, params
    
    @staticmethod
    def insert(table: str, values: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """
        Безопасный INSERT запрос
        
        Example:
            query, params = SafeQueryBuilder.insert(
                table="users",
                values={"username": "john", "email": "john@example.com"}
            )
        """
        columns = list(values.keys())
        params = {}
        
        placeholders = []
        for i, (key, value) in enumerate(values.items()):
            param_name = f"param_{i}"
            placeholders.append(f":{param_name}")
            params[param_name] = value
        
        columns_str = ", ".join(columns)
        placeholders_str = ", ".join(placeholders)
        
        query = f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders_str})"
        return query, params
    
    @staticmethod
    def update(
        table: str,
        values: Dict[str, Any],
        conditions: Dict[str, Any]
    ) -> tuple[str, Dict[str, Any]]:
        """
        Безопасный UPDATE запрос
        
        Example:
            query, params = SafeQueryBuilder.update(
                table="users",
                values={"status": "inactive"},
                conditions={"user_id": 123}
            )
        """
        params = {}
        
        # SET clause
        set_clauses = []
        for i, (key, value) in enumerate(values.items()):
            param_name = f"set_{i}"
            set_clauses.append(f"{key} = :{param_name}")
            params[param_name] = value
        
        # WHERE clause
        where_clauses = []
        for i, (key, value) in enumerate(conditions.items()):
            param_name = f"where_{i}"
            where_clauses.append(f"{key} = :{param_name}")
            params[param_name] = value
        
        query = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE {' AND '.join(where_clauses)}"
        return query, params
    
    @staticmethod
    def delete(table: str, conditions: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """
        Безопасный DELETE запрос
        
        Example:
            query, params = SafeQueryBuilder.delete(
                table="users",
                conditions={"user_id": 123}
            )
        """
        params = {}
        
        where_clauses = []
        for i, (key, value) in enumerate(conditions.items()):
            param_name = f"param_{i}"
            where_clauses.append(f"{key} = :{param_name}")
            params[param_name] = value
        
        query = f"DELETE FROM {table} WHERE {' AND '.join(where_clauses)}"
        return query, params


# ============================================================================
# SQLALCHEMY SAFE LAYER
# ============================================================================

class SafeSQLAlchemyRepository:
    """Безопасный репозиторий с использованием SQLAlchemy"""
    
    def __init__(self, connection_string: str):
        self.engine = create_engine(connection_string, echo=True)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.metadata = MetaData()
    
    @contextmanager
    def get_session(self) -> Session:
        """Context manager для сессий"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def execute_safe_query(
        self,
        query_str: str,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Выполнение безопасного параметризованного запроса
        
        Example:
            results = repo.execute_safe_query(
                "SELECT * FROM users WHERE username = :username",
                {"username": "john"}
            )
        """
        with self.get_session() as session:
            # КРИТИЧНО: Используем text() с bind parameters
            query = text(query_str)
            result = session.execute(query, params)
            
            # Преобразование в список словарей
            columns = result.keys()
            return [dict(zip(columns, row)) for row in result.fetchall()]
    
    def select_users_by_status(self, status: str) -> List[Dict[str, Any]]:
        """Пример: безопасный SELECT с параметрами"""
        query, params = SafeQueryBuilder.select(
            table="users",
            columns=["id", "username", "email", "status"],
            conditions={"status": status}
        )
        return self.execute_safe_query(query, params)
    
    def insert_user(self, user_data: Dict[str, Any]) -> int:
        """Пример: безопасный INSERT"""
        query, params = SafeQueryBuilder.insert(
            table="users",
            values=user_data
        )
        
        with self.get_session() as session:
            result = session.execute(text(query), params)
            return result.lastrowid
    
    def update_user_status(self, user_id: int, new_status: str):
        """Пример: безопасный UPDATE"""
        query, params = SafeQueryBuilder.update(
            table="users",
            values={"status": new_status},
            conditions={"id": user_id}
        )
        
        with self.get_session() as session:
            session.execute(text(query), params)


# ============================================================================
# ASYNC POSTGRESQL LAYER (asyncpg)
# ============================================================================

class SafeAsyncPostgresRepository:
    """Безопасный асинхронный репозиторий для PostgreSQL"""
    
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None
    
    async def initialize(self):
        """Инициализация connection pool"""
        self.pool = await asyncpg.create_pool(
            self.dsn,
            min_size=10,
            max_size=20,
            command_timeout=60
        )
        logger.info("AsyncPG pool initialized")
    
    async def close(self):
        """Закрытие pool"""
        if self.pool:
            await self.pool.close()
    
    async def execute_safe_query(
        self,
        query: str,
        *args
    ) -> List[Dict[str, Any]]:
        """
        Выполнение безопасного запроса с позиционными параметрами
        
        Example:
            results = await repo.execute_safe_query(
                "SELECT * FROM users WHERE username = $1 AND status = $2",
                "john",
                "active"
            )
        """
        async with self.pool.acquire() as connection:
            # asyncpg использует $1, $2, ... для параметров
            rows = await connection.fetch(query, *args)
            return [dict(row) for row in rows]
    
    async def fetch_users_by_email_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Пример: безопасный поиск с LIKE"""
        # КРИТИЧНО: Параметризация для LIKE
        query = """
            SELECT id, username, email, created_at
            FROM users
            WHERE email LIKE $1
            ORDER BY created_at DESC
            LIMIT 100
        """
        # Добавляем % в параметр, НЕ в запрос
        pattern = f"%@{domain}"
        return await self.execute_safe_query(query, pattern)
    
    async def insert_user_safe(self, username: str, email: str, password_hash: str) -> int:
        """Пример: безопасный INSERT с RETURNING"""
        query = """
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES ($1, $2, $3, NOW())
            RETURNING id
        """
        async with self.pool.acquire() as connection:
            user_id = await connection.fetchval(query, username, email, password_hash)
            return user_id
    
    async def bulk_insert_safe(self, users: List[Dict[str, str]]):
        """Пример: безопасный bulk INSERT"""
        query = """
            INSERT INTO users (username, email, password_hash)
            VALUES ($1, $2, $3)
        """
        async with self.pool.acquire() as connection:
            # Используем executemany для batch insert
            await connection.executemany(
                query,
                [(u['username'], u['email'], u['password_hash']) for u in users]
            )


# ============================================================================
# ORM ПРИМЕРЫ (SQLAlchemy ORM)
# ============================================================================

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    """Модель пользователя"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    status = Column(String(20), default='active')


class SafeORMRepository:
    """Безопасный ORM-репозиторий"""
    
    def __init__(self, connection_string: str):
        self.engine = create_engine(connection_string)
        self.SessionLocal = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Безопасный поиск через ORM"""
        with self.SessionLocal() as session:
            # ORM автоматически параметризует запросы
            user = session.query(User).filter(
                User.username == username
            ).first()
            return user
    
    def search_users_by_email_pattern(self, pattern: str) -> List[User]:
        """Безопасный поиск с LIKE через ORM"""
        with self.SessionLocal() as session:
            # ORM параметризует даже LIKE
            users = session.query(User).filter(
                User.email.like(f"%{pattern}%")
            ).all()
            return users
    
    def create_user_safe(self, username: str, email: str) -> User:
        """Безопасное создание через ORM"""
        with self.SessionLocal() as session:
            user = User(username=username, email=email)
            session.add(user)
            session.commit()
            session.refresh(user)
            return user


# ============================================================================
# ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ
# ============================================================================

async def example_async_usage():
    """Пример использования асинхронного репозитория"""
    
    # Инициализация
    repo = SafeAsyncPostgresRepository(
        dsn="postgresql://user:password@localhost/dbname"
    )
    await repo.initialize()
    
    try:
        # Безопасный SELECT
        users = await repo.fetch_users_by_email_domain("example.com")
        print(f"Found {len(users)} users")
        
        # Безопасный INSERT
        user_id = await repo.insert_user_safe(
            username="john_doe",
            email="john@example.com",
            password_hash="hashed_password_here"
        )
        print(f"Created user with ID: {user_id}")
        
        # Bulk insert
        new_users = [
            {"username": "user1", "email": "user1@example.com", "password_hash": "hash1"},
            {"username": "user2", "email": "user2@example.com", "password_hash": "hash2"},
        ]
        await repo.bulk_insert_safe(new_users)
        
    finally:
        await repo.close()


def example_sync_usage():
    """Пример использования синхронного репозитория"""
    
    # Инициализация
    repo = SafeSQLAlchemyRepository(
        connection_string="sqlite:///example.db"
    )
    
    # Безопасный SELECT
    active_users = repo.select_users_by_status("active")
    print(f"Active users: {len(active_users)}")
    
    # Безопасный INSERT
    user_id = repo.insert_user({
        "username": "jane_doe",
        "email": "jane@example.com",
        "status": "active"
    })
    print(f"Created user with ID: {user_id}")
    
    # Безопасный UPDATE
    repo.update_user_status(user_id, "inactive")


def example_orm_usage():
    """Пример использования ORM"""
    
    repo = SafeORMRepository("sqlite:///example.db")
    
    # Безопасный поиск
    user = repo.get_user_by_username("john_doe")
    if user:
        print(f"Found user: {user.email}")
    
    # Безопасный search
    gmail_users = repo.search_users_by_email_pattern("gmail.com")
    print(f"Gmail users: {len(gmail_users)}")
    
    # Безопасное создание
    new_user = repo.create_user_safe("new_user", "new@example.com")
    print(f"Created user: {new_user.id}")


# ============================================================================
# ANTI-PATTERNS: ЧТО НИКОГДА НЕ ДЕЛАТЬ
# ============================================================================

def DANGEROUS_EXAMPLES():
    """
    ❌ ОПАСНЫЕ ПАТТЕРНЫ - НИКОГДА ТАК НЕ ДЕЛАЙТЕ!
    """
    
    # ❌ ОПАСНО: Конкатенация строк
    def vulnerable_query_1(username: str):
        query = f"SELECT * FROM users WHERE username = '{username}'"  # ОПАСНО!
        # Возможна инъекция: username = "admin' OR '1'='1"
        return query
    
    # ❌ ОПАСНО: Форматирование строк
    def vulnerable_query_2(email: str):
        query = "SELECT * FROM users WHERE email = '%s'" % email  # ОПАСНО!
        return query
    
    # ❌ ОПАСНО: .format()
    def vulnerable_query_3(status: str):
        query = "SELECT * FROM users WHERE status = '{}'".format(status)  # ОПАСНО!
        return query
    
    # ❌ ОПАСНО: Неэкранированный LIKE
    def vulnerable_query_4(search: str):
        query = f"SELECT * FROM users WHERE name LIKE '%{search}%'"  # ОПАСНО!
        return query


def SAFE_ALTERNATIVES():
    """
    ✅ БЕЗОПАСНЫЕ АЛЬТЕРНАТИВЫ
    """
    
    # ✅ БЕЗОПАСНО: Параметризованный запрос (SQLAlchemy)
    def safe_query_1(session: Session, username: str):
        query = text("SELECT * FROM users WHERE username = :username")
        return session.execute(query, {"username": username})
    
    # ✅ БЕЗОПАСНО: Параметризованный запрос (asyncpg)
    async def safe_query_2(connection, email: str):
        query = "SELECT * FROM users WHERE email = $1"
        return await connection.fetch(query, email)
    
    # ✅ БЕЗОПАСНО: ORM query
    def safe_query_3(session: Session, status: str):
        return session.query(User).filter(User.status == status).all()
    
    # ✅ БЕЗОПАСНО: Параметризованный LIKE
    def safe_query_4(session: Session, search: str):
        query = text("SELECT * FROM users WHERE name LIKE :pattern")
        pattern = f"%{search}%"  # Параметр формируется безопасно
        return session.execute(query, {"pattern": pattern})


if __name__ == "__main__":
    print("=== Примеры безопасных SQL-запросов ===\n")
    
    # Демонстрация Query Builder
    print("1. Query Builder примеры:")
    
    query, params = SafeQueryBuilder.select(
        table="users",
        columns=["id", "username"],
        conditions={"status": "active"},
        limit=10
    )
    print(f"SELECT: {query}")
    print(f"Params: {params}\n")
    
    query, params = SafeQueryBuilder.insert(
        table="users",
        values={"username": "john", "email": "john@example.com"}
    )
    print(f"INSERT: {query}")
    print(f"Params: {params}\n")
    
    print("2. Запустите example_sync_usage() или example_async_usage() для полных примеров")
