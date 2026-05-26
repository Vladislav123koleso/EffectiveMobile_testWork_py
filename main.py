from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

DB_PATH = "app.db"

app = FastAPI(title="Simple Auth API", version="0.1")
bearer_scheme = HTTPBearer(auto_error=False)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()
    return f"{salt}${pwd_hash}"


def verify_password(password: str, stored_hash: str) -> bool:
    parts = stored_hash.split("$", 1)
    if len(parts) != 2:
        return False
    salt, _ = parts
    return hash_password(password, salt) == stored_hash


def get_or_create_role(conn: sqlite3.Connection, name: str, description: str) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO roles(name, description) VALUES(?, ?)",
        (name, description),
    )
    row = conn.execute("SELECT id FROM roles WHERE name = ?", (name,)).fetchone()
    return int(row["id"])


def get_or_create_permission(
    conn: sqlite3.Connection, resource: str, action: str, description: str
) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO permissions(resource, action, description) VALUES(?, ?, ?)",
        (resource, action, description),
    )
    row = conn.execute(
        "SELECT id FROM permissions WHERE resource = ? AND action = ?",
        (resource, action),
    ).fetchone()
    return int(row["id"])


def get_or_create_user(
    conn: sqlite3.Connection,
    first_name: str,
    last_name: str,
    middle_name: str,
    email: str,
    password: str,
) -> int:
    now = utc_now()
    conn.execute(
        """
        INSERT OR IGNORE INTO users(first_name, last_name, middle_name, email, password_hash, is_active, created_at, updated_at)
        VALUES(?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            first_name,
            last_name,
            middle_name,
            email,
            hash_password(password),
            now,
            now,
        ),
    )
    row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    return int(row["id"])


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                middle_name TEXT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                description TEXT,
                UNIQUE(resource, action)
            );

            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                permission_id INTEGER NOT NULL,
                PRIMARY KEY(role_id, permission_id),
                FOREIGN KEY(role_id) REFERENCES roles(id),
                FOREIGN KEY(permission_id) REFERENCES permissions(id)
            );

            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                PRIMARY KEY(user_id, role_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(role_id) REFERENCES roles(id)
            );
            """
        )

        admin_role_id = get_or_create_role(conn, "admin", "Администратор")
        user_role_id = get_or_create_role(conn, "user", "Обычный пользователь")

        permission_map = {
            "rules_read": get_or_create_permission(
                conn, "rules", "read", "Просмотр правил доступа"
            ),
            "rules_write": get_or_create_permission(
                conn, "rules", "write", "Изменение правил доступа"
            ),
            "projects_read": get_or_create_permission(
                conn, "projects", "read", "Просмотр списка проектов"
            ),
            "reports_read": get_or_create_permission(
                conn, "reports", "read", "Просмотр отчетов"
            ),
            "admin_panel_read": get_or_create_permission(
                conn, "admin_panel", "read", "Доступ к админ-панели"
            ),
        }

        for permission_id in permission_map.values():
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES(?, ?)",
                (admin_role_id, permission_id),
            )

        conn.execute(
            "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES(?, ?)",
            (user_role_id, permission_map["projects_read"]),
        )

        admin_user_id = get_or_create_user(
            conn,
            first_name="Admin",
            last_name="System",
            middle_name="",
            email="admin@example.com",
            password="Admin123!",
        )
        regular_user_id = get_or_create_user(
            conn,
            first_name="Ivan",
            last_name="Petrov",
            middle_name="Ivanovich",
            email="user@example.com",
            password="User123!",
        )

        conn.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)",
            (admin_user_id, admin_role_id),
        )
        conn.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)",
            (regular_user_id, user_role_id),
        )


class RegisterIn(BaseModel):
    first_name: str
    last_name: str
    middle_name: Optional[str] = ""
    email: str
    password: str
    password_repeat: str


class LoginIn(BaseModel):
    email: str
    password: str


class UpdateProfileIn(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    middle_name: Optional[str] = None
    email: Optional[str] = None
    new_password: Optional[str] = None
    password_repeat: Optional[str] = None


class ChangeRolePermissionIn(BaseModel):
    permission_id: int


class ChangeUserRoleIn(BaseModel):
    role_id: int


def get_current_session_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Необходима авторизация")

    token = credentials.credentials.strip()
    if not token:
        raise HTTPException(status_code=401, detail="Необходима авторизация")

    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                s.id AS session_id,
                s.token AS token,
                u.id AS user_id,
                u.first_name,
                u.last_name,
                u.middle_name,
                u.email,
                u.is_active
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ? AND s.is_active = 1 AND u.is_active = 1
            """,
            (token,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Необходима авторизация")

    return dict(row)


def has_permission(user_id: int, resource: str, action: str) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM user_roles ur
            JOIN role_permissions rp ON rp.role_id = ur.role_id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = ?
              AND (p.resource = ? OR p.resource = '*')
              AND (p.action = ? OR p.action = '*')
            LIMIT 1
            """,
            (user_id, resource, action),
        ).fetchone()
    return row is not None


def require_permission(resource: str, action: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def dependency(user: dict[str, Any] = Depends(get_current_session_user)) -> dict[str, Any]:
        if not has_permission(int(user["user_id"]), resource, action):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dependency


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "Simple auth backend is running"}


@app.post("/auth/register")
def register(data: RegisterIn) -> dict[str, Any]:
    if data.password != data.password_repeat:
        raise HTTPException(status_code=400, detail="Пароли не совпадают")

    if "@" not in data.email:
        raise HTTPException(status_code=400, detail="Неверный email")

    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Пароль слишком короткий")

    now = utc_now()
    email = data.email.strip().lower()
    try:
        with get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users(first_name, last_name, middle_name, email, password_hash, is_active, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    data.first_name.strip(),
                    data.last_name.strip(),
                    (data.middle_name or "").strip(),
                    email,
                    hash_password(data.password),
                    now,
                    now,
                ),
            )
            user_id = int(cursor.lastrowid)

            user_role_row = conn.execute(
                "SELECT id FROM roles WHERE name = 'user'"
            ).fetchone()
            if user_role_row:
                conn.execute(
                    "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)",
                    (user_id, int(user_role_row["id"])),
                )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Пользователь с таким email уже есть")

    return {"message": "Пользователь зарегистрирован", "user_id": user_id}


@app.post("/auth/login")
def login(data: LoginIn) -> dict[str, Any]:
    email = data.email.strip().lower()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, first_name, last_name, middle_name, email, password_hash, is_active FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if row is None or not verify_password(data.password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Неверный email или пароль")

        if int(row["is_active"]) == 0:
            raise HTTPException(status_code=400, detail="Пользователь деактивирован")

        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions(user_id, token, is_active, created_at) VALUES(?, ?, 1, ?)",
            (int(row["id"]), token, utc_now()),
        )

    return {
        "message": "Успешный вход",
        "token": token,
        "user": {
            "id": int(row["id"]),
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "middle_name": row["middle_name"],
            "email": row["email"],
        },
    }


@app.post("/auth/logout")
def logout(current: dict[str, Any] = Depends(get_current_session_user)) -> dict[str, str]:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET is_active = 0 WHERE id = ?",
            (int(current["session_id"]),),
        )
    return {"message": "Вы вышли из системы"}


@app.get("/users/me")
def get_me(current: dict[str, Any] = Depends(get_current_session_user)) -> dict[str, Any]:
    return {
        "id": int(current["user_id"]),
        "first_name": current["first_name"],
        "last_name": current["last_name"],
        "middle_name": current["middle_name"],
        "email": current["email"],
        "is_active": bool(current["is_active"]),
    }


@app.patch("/users/me")
def update_me(
    data: UpdateProfileIn,
    current: dict[str, Any] = Depends(get_current_session_user),
) -> dict[str, Any]:
    payload = data.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=400, detail="Нет данных для обновления")

    if "new_password" in payload or "password_repeat" in payload:
        if payload.get("new_password") != payload.get("password_repeat"):
            raise HTTPException(status_code=400, detail="Новые пароли не совпадают")
        if not payload.get("new_password"):
            raise HTTPException(status_code=400, detail="Новый пароль пустой")

    fields: list[str] = []
    values: list[Any] = []

    if "first_name" in payload:
        fields.append("first_name = ?")
        values.append((payload.get("first_name") or "").strip())
    if "last_name" in payload:
        fields.append("last_name = ?")
        values.append((payload.get("last_name") or "").strip())
    if "middle_name" in payload:
        fields.append("middle_name = ?")
        values.append((payload.get("middle_name") or "").strip())
    if "email" in payload:
        email = (payload.get("email") or "").strip().lower()
        if "@" not in email:
            raise HTTPException(status_code=400, detail="Неверный email")
        fields.append("email = ?")
        values.append(email)
    if "new_password" in payload:
        if len(payload["new_password"]) < 6:
            raise HTTPException(status_code=400, detail="Пароль слишком короткий")
        fields.append("password_hash = ?")
        values.append(hash_password(payload["new_password"]))

    fields.append("updated_at = ?")
    values.append(utc_now())
    values.append(int(current["user_id"]))

    query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"

    try:
        with get_connection() as conn:
            conn.execute(query, values)
            row = conn.execute(
                "SELECT id, first_name, last_name, middle_name, email, is_active FROM users WHERE id = ?",
                (int(current["user_id"]),),
            ).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email уже занят")

    return {
        "message": "Профиль обновлен",
        "user": {
            "id": int(row["id"]),
            "first_name": row["first_name"],
            "last_name": row["last_name"],
            "middle_name": row["middle_name"],
            "email": row["email"],
            "is_active": bool(row["is_active"]),
        },
    }


@app.delete("/users/me")
def soft_delete_me(current: dict[str, Any] = Depends(get_current_session_user)) -> dict[str, str]:
    user_id = int(current["user_id"])
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?",
            (utc_now(), user_id),
        )
        conn.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))

    return {
        "message": "Аккаунт деактивирован. Вход в систему для этого пользователя запрещен"
    }


@app.get("/admin/roles")
def get_roles(
    _: dict[str, Any] = Depends(require_permission("rules", "read")),
) -> dict[str, Any]:
    with get_connection() as conn:
        rows = conn.execute("SELECT id, name, description FROM roles ORDER BY id").fetchall()
    return {"roles": [dict(r) for r in rows]}


@app.get("/admin/permissions")
def get_permissions(
    _: dict[str, Any] = Depends(require_permission("rules", "read")),
) -> dict[str, Any]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, resource, action, description FROM permissions ORDER BY id"
        ).fetchall()
    return {"permissions": [dict(r) for r in rows]}


@app.get("/admin/rules")
def get_rules(
    _: dict[str, Any] = Depends(require_permission("rules", "read")),
) -> dict[str, Any]:
    with get_connection() as conn:
        role_permissions = conn.execute(
            """
            SELECT
                r.id AS role_id,
                r.name AS role_name,
                p.id AS permission_id,
                p.resource,
                p.action
            FROM roles r
            LEFT JOIN role_permissions rp ON rp.role_id = r.id
            LEFT JOIN permissions p ON p.id = rp.permission_id
            ORDER BY r.id, p.id
            """
        ).fetchall()

        user_roles = conn.execute(
            """
            SELECT
                u.id AS user_id,
                u.email,
                u.is_active,
                r.id AS role_id,
                r.name AS role_name
            FROM users u
            LEFT JOIN user_roles ur ON ur.user_id = u.id
            LEFT JOIN roles r ON r.id = ur.role_id
            ORDER BY u.id, r.id
            """
        ).fetchall()

    return {
        "role_permissions": [dict(r) for r in role_permissions],
        "user_roles": [dict(r) for r in user_roles],
    }


@app.post("/admin/roles/{role_id}/permissions")
def add_permission_to_role(
    role_id: int,
    data: ChangeRolePermissionIn,
    _: dict[str, Any] = Depends(require_permission("rules", "write")),
) -> dict[str, str]:
    with get_connection() as conn:
        role = conn.execute("SELECT id FROM roles WHERE id = ?", (role_id,)).fetchone()
        permission = conn.execute(
            "SELECT id FROM permissions WHERE id = ?", (data.permission_id,)
        ).fetchone()

        if role is None or permission is None:
            raise HTTPException(status_code=404, detail="Роль или право не найдены")

        conn.execute(
            "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES(?, ?)",
            (role_id, data.permission_id),
        )

    return {"message": "Право добавлено к роли"}


@app.delete("/admin/roles/{role_id}/permissions/{permission_id}")
def remove_permission_from_role(
    role_id: int,
    permission_id: int,
    _: dict[str, Any] = Depends(require_permission("rules", "write")),
) -> dict[str, str]:
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            (role_id, permission_id),
        )
    return {"message": "Право удалено у роли"}


@app.post("/admin/users/{user_id}/roles")
def add_role_to_user(
    user_id: int,
    data: ChangeUserRoleIn,
    _: dict[str, Any] = Depends(require_permission("rules", "write")),
) -> dict[str, str]:
    with get_connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        role = conn.execute("SELECT id FROM roles WHERE id = ?", (data.role_id,)).fetchone()

        if user is None or role is None:
            raise HTTPException(status_code=404, detail="Пользователь или роль не найдены")

        conn.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?, ?)",
            (user_id, data.role_id),
        )

    return {"message": "Роль добавлена пользователю"}


@app.delete("/admin/users/{user_id}/roles/{role_id}")
def remove_role_from_user(
    user_id: int,
    role_id: int,
    _: dict[str, Any] = Depends(require_permission("rules", "write")),
) -> dict[str, str]:
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
            (user_id, role_id),
        )
    return {"message": "Роль удалена у пользователя"}


@app.get("/mock/projects")
def list_mock_projects(
    _: dict[str, Any] = Depends(require_permission("projects", "read")),
) -> dict[str, Any]:
    return {
        "projects": [
            {"id": 1, "name": "Project A"},
            {"id": 2, "name": "Project B"},
        ]
    }


@app.get("/mock/reports")
def list_mock_reports(
    _: dict[str, Any] = Depends(require_permission("reports", "read")),
) -> dict[str, Any]:
    return {
        "reports": [
            {"id": 101, "name": "Financial report"},
            {"id": 102, "name": "Marketing report"},
        ]
    }


@app.get("/mock/admin-panel")
def open_mock_admin_panel(
    _: dict[str, Any] = Depends(require_permission("admin_panel", "read")),
) -> dict[str, Any]:
    return {"message": "Содержимое админ-панели (mock)"}
