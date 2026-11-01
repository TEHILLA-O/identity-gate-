"""Northstar Directory, a simulated downstream SCIM 2.0 service.

Supported subset: Users, Groups, filters on userName, externalId, displayName
and members.value, patch, and pagination. Bulk, sort, and ETag are not supported.
"""

from __future__ import annotations

import os
import secrets
from hmac import compare_digest

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import JSON, Boolean, ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

CORE_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
CORE_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
ACCESS = "urn:northstar:params:scim:schemas:extension:access:1.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(128), unique=True)
    user_name: Mapped[str] = mapped_column(String(128), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    given_name: Mapped[str] = mapped_column(String(120), default="")
    family_name: Mapped[str] = mapped_column(String(120), default="")
    email: Mapped[str] = mapped_column(String(254), default="")
    title: Mapped[str] = mapped_column(String(160), default="")
    department: Mapped[str] = mapped_column(String(80), default="")
    employee_number: Mapped[str] = mapped_column(String(64), default="")
    roles: Mapped[list] = mapped_column(JSON, default=list)


class Group(Base):
    __tablename__ = "groups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(160), unique=True)
    external_id: Mapped[str] = mapped_column(String(128), default="")


class Membership(Base):
    __tablename__ = "memberships"
    group_id: Mapped[str] = mapped_column(ForeignKey("groups.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)


def create_app(database_url: str = "sqlite:///directory.db", token: str = "directory-token") -> FastAPI:
    engine_kwargs = {"pool_pre_ping": not database_url.startswith("sqlite")}
    if database_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **engine_kwargs)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    app = FastAPI(title="Northstar Directory")

    def db() -> Session:
        return sessions()

    def authorized(request: Request) -> bool:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return False
        return compare_digest(header.split(" ", 1)[1], token)

    def guard(request: Request):
        if not authorized(request):
            return error(401, "Authentication is required.")
        return None

    def user_json(session: Session, user: User) -> dict:
        groups = session.scalars(select(Group).join(Membership, Membership.group_id == Group.id).where(Membership.user_id == user.id)).all()
        return {
            "schemas": [CORE_USER, ENTERPRISE, ACCESS],
            "id": user.id,
            "externalId": user.external_id,
            "userName": user.user_name,
            "active": user.active,
            "title": user.title,
            "name": {"givenName": user.given_name, "familyName": user.family_name},
            "emails": [{"value": user.email, "type": "work", "primary": True}] if user.email else [],
            "groups": [{"value": group.id, "display": group.display_name} for group in groups],
            ENTERPRISE: {"employeeNumber": user.employee_number, "department": user.department},
            ACCESS: {"roles": user.roles or []},
        }

    def group_json(session: Session, group: Group, include_members: bool = True) -> dict:
        body = {"schemas": [CORE_GROUP], "id": group.id, "displayName": group.display_name, "externalId": group.external_id}
        if include_members:
            users = session.scalars(select(User).join(Membership, Membership.user_id == User.id).where(Membership.group_id == group.id)).all()
            body["members"] = [{"value": user.id, "display": user.user_name, "type": "User"} for user in users]
        return body

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/scim/v2/ServiceProviderConfig")
    def service_provider(request: Request):
        denied = guard(request)
        if denied:
            return denied
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 100},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer", "description": "Static service token for the simulated directory."}],
        }

    @app.get("/scim/v2/Schemas")
    def schemas(request: Request):
        denied = guard(request)
        if denied:
            return denied
        return {"schemas": [LIST_SCHEMA], "totalResults": 2, "Resources": [{"id": CORE_USER, "name": "User"}, {"id": CORE_GROUP, "name": "Group"}]}

    @app.get("/scim/v2/ResourceTypes")
    def resource_types(request: Request):
        denied = guard(request)
        if denied:
            return denied
        return {"schemas": [LIST_SCHEMA], "totalResults": 2, "Resources": [{"name": "User", "endpoint": "/Users"}, {"name": "Group", "endpoint": "/Groups"}]}

    @app.get("/scim/v2/Users")
    def list_users(request: Request, filter: str = "", startIndex: int = 1, count: int = 100):
        denied = guard(request)
        if denied:
            return denied
        session = db()
        try:
            rows = session.scalars(select(User).order_by(User.user_name)).all()
            rows = [row for row in rows if _match_user(row, filter)]
            window = rows[max(startIndex, 1) - 1 : max(startIndex, 1) - 1 + min(count, 100)]
            return {"schemas": [LIST_SCHEMA], "totalResults": len(rows), "startIndex": startIndex, "itemsPerPage": len(window), "Resources": [user_json(session, row) for row in window]}
        finally:
            session.close()

    @app.post("/scim/v2/Users", status_code=201)
    async def create_user(request: Request):
        denied = guard(request)
        if denied:
            return denied
        payload = await request.json()
        session = db()
        try:
            external_id = payload.get("externalId") or payload.get("userName")
            if session.scalar(select(User).where((User.external_id == external_id) | (User.user_name == payload.get("userName")))):
                return error(409, "User already exists.", "uniqueness")
            user = _user_from(payload, external_id)
            session.add(user)
            session.commit()
            return JSONResponse(user_json(session, user), status_code=201)
        finally:
            session.close()

    @app.get("/scim/v2/Users/{user_id}")
    def get_user(user_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        session = db()
        try:
            user = session.get(User, user_id)
            if user is None:
                return error(404, "User was not found.")
            return user_json(session, user)
        finally:
            session.close()

    @app.put("/scim/v2/Users/{user_id}")
    async def replace_user(user_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        payload = await request.json()
        session = db()
        try:
            user = session.get(User, user_id)
            if user is None:
                return error(404, "User was not found.")
            _apply_user(user, payload)
            session.commit()
            return user_json(session, user)
        finally:
            session.close()

    @app.patch("/scim/v2/Users/{user_id}")
    async def patch_user(user_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        payload = await request.json()
        session = db()
        try:
            user = session.get(User, user_id)
            if user is None:
                return error(404, "User was not found.")
            for operation in payload.get("Operations") or []:
                path = operation.get("path")
                value = operation.get("value")
                if path == "active":
                    user.active = bool(value)
                elif path == "title":
                    user.title = value or ""
                elif path == "name.givenName":
                    user.given_name = value or ""
                elif path == "name.familyName":
                    user.family_name = value or ""
            session.commit()
            return user_json(session, user)
        finally:
            session.close()

    @app.delete("/scim/v2/Users/{user_id}", status_code=204)
    def delete_user(user_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        session = db()
        try:
            user = session.get(User, user_id)
            if user is None:
                return error(404, "User was not found.")
            for membership in session.scalars(select(Membership).where(Membership.user_id == user_id)).all():
                session.delete(membership)
            session.delete(user)
            session.commit()
            return JSONResponse(status_code=204, content=None)
        finally:
            session.close()

    @app.get("/scim/v2/Groups")
    def list_groups(request: Request, filter: str = "", startIndex: int = 1, count: int = 100):
        denied = guard(request)
        if denied:
            return denied
        session = db()
        try:
            rows = session.scalars(select(Group).order_by(Group.display_name)).all()
            if "displayName eq" in filter:
                name = _quoted(filter)
                rows = [row for row in rows if row.display_name == name]
            elif "members.value eq" in filter:
                user_id = _quoted(filter)
                member_groups = set(session.scalars(select(Membership.group_id).where(Membership.user_id == user_id)).all())
                rows = [row for row in rows if row.id in member_groups]
            window = rows[max(startIndex, 1) - 1 : max(startIndex, 1) - 1 + min(count, 100)]
            include_members = "members" in request.query_params.get("attributes", "members")
            return {"schemas": [LIST_SCHEMA], "totalResults": len(rows), "startIndex": startIndex, "itemsPerPage": len(window), "Resources": [group_json(session, row, include_members) for row in window]}
        finally:
            session.close()

    @app.post("/scim/v2/Groups", status_code=201)
    async def create_group(request: Request):
        denied = guard(request)
        if denied:
            return denied
        payload = await request.json()
        if payload.get("members"):
            return error(400, "Members cannot be set while creating a group.")
        session = db()
        try:
            if session.scalar(select(Group).where(Group.display_name == payload.get("displayName"))):
                return error(409, "Group already exists.", "uniqueness")
            group = Group(id=secrets.token_hex(16), display_name=payload["displayName"], external_id=payload.get("externalId") or payload["displayName"])
            session.add(group)
            session.commit()
            return JSONResponse(group_json(session, group), status_code=201)
        finally:
            session.close()

    @app.get("/scim/v2/Groups/{group_id}")
    def get_group(group_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        session = db()
        try:
            group = session.get(Group, group_id)
            if group is None:
                return error(404, "Group was not found.")
            return group_json(session, group)
        finally:
            session.close()

    @app.patch("/scim/v2/Groups/{group_id}")
    async def patch_group(group_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        payload = await request.json()
        session = db()
        try:
            group = session.get(Group, group_id)
            if group is None:
                return error(404, "Group was not found.")
            for operation in payload.get("Operations") or []:
                op = (operation.get("op") or "").lower()
                path = operation.get("path") or ""
                if op == "replace" and path == "displayName":
                    group.display_name = operation.get("value")
                elif op == "add" and path == "members":
                    member_id = operation.get("value")
                    if isinstance(member_id, dict):
                        member_id = member_id.get("value")
                    if session.get(Membership, (group_id, member_id)) is None:
                        session.add(Membership(group_id=group_id, user_id=member_id))
                elif op == "remove" and path.startswith("members"):
                    member_id = _quoted(path)
                    membership = session.get(Membership, (group_id, member_id))
                    if membership:
                        session.delete(membership)
            session.commit()
            return group_json(session, group)
        finally:
            session.close()

    @app.delete("/scim/v2/Groups/{group_id}", status_code=204)
    def delete_group(group_id: str, request: Request):
        denied = guard(request)
        if denied:
            return denied
        session = db()
        try:
            group = session.get(Group, group_id)
            if group is None:
                return error(404, "Group was not found.")
            for membership in session.scalars(select(Membership).where(Membership.group_id == group_id)).all():
                session.delete(membership)
            session.delete(group)
            session.commit()
            return JSONResponse(status_code=204, content=None)
        finally:
            session.close()

    return app


def _user_from(payload: dict, external_id: str) -> User:
    user = User(id=secrets.token_hex(16), external_id=external_id, user_name=payload["userName"])
    _apply_user(user, payload)
    return user


def _apply_user(user: User, payload: dict) -> None:
    name = payload.get("name") or {}
    emails = payload.get("emails") or []
    enterprise = payload.get(ENTERPRISE) or {}
    access = payload.get(ACCESS) or {}
    user.user_name = payload.get("userName") or user.user_name
    user.external_id = payload.get("externalId") or user.external_id
    user.active = bool(payload.get("active", user.active))
    user.given_name = name.get("givenName") or user.given_name
    user.family_name = name.get("familyName") or user.family_name
    user.email = (emails[0].get("value") if emails else user.email) or ""
    user.title = payload.get("title") or user.title
    user.department = enterprise.get("department") or user.department
    user.employee_number = enterprise.get("employeeNumber") or user.employee_number
    if "roles" in access:
        user.roles = access.get("roles") or []


def _match_user(user: User, expression: str) -> bool:
    if not expression:
        return True
    if "userName eq" in expression:
        return user.user_name == _quoted(expression)
    if "externalId eq" in expression:
        return user.external_id == _quoted(expression)
    return False


def _quoted(expression: str) -> str:
    if '"' not in expression:
        return ""
    return expression.split('"', 2)[1]


def error(status: int, detail: str, scim_type: str | None = None):
    body = {"schemas": [ERROR], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status)


app = create_app(token=os.environ.get("DIRECTORY_TOKEN", "directory-token"))
