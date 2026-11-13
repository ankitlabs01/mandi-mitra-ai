"""Mandi Mitra AI API — updated with user-specific crop protection."""

from contextlib import asynccontextmanager
from pathlib import Path
import sqlite3
import os
import hashlib
import hmac
import secrets
import base64
import json
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


DB_PATH = Path(__file__).with_name("mandi_mitra.db")


# --------------------------------------------------
# DEMO MARKET DATA
# --------------------------------------------------

DEMO_MARKETS = [
    {
        "id": 1, "crop": "Tomato", "market": "Anekal",
        "min": 1400, "max": 2100, "modal": 1800,
        "trend": "↑ 4.2%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
    {
        "id": 2, "crop": "Tomato", "market": "Ramanagara",
        "min": 1550, "max": 2250, "modal": 1950,
        "trend": "↑ 6.1%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
    {
        "id": 3, "crop": "Tomato", "market": "Hosur",
        "min": 1300, "max": 2000, "modal": 1720,
        "trend": "↓ 1.4%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
    {
        "id": 4, "crop": "Onion", "market": "Anekal",
        "min": 1700, "max": 2400, "modal": 2100,
        "trend": "↑ 2.5%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
    {
        "id": 5, "crop": "Onion", "market": "Kolar",
        "min": 1600, "max": 2300, "modal": 1950,
        "trend": "↑ 1.1%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
    {
        "id": 6, "crop": "Ragi", "market": "Ramanagara",
        "min": 3200, "max": 3800, "modal": 3500,
        "trend": "→ 0.2%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
    {
        "id": 7, "crop": "Maize", "market": "Kolar",
        "min": 1900, "max": 2250, "modal": 2100,
        "trend": "↓ 0.8%", "updated": "Demo sample",
        "source": "Illustrative data"
    },
]


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    with sqlite3.connect(DB_PATH) as db:

        # Users table
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'farmer',
                village TEXT DEFAULT '',
                district TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Crops table with user ownership
        db.execute("""
            CREATE TABLE IF NOT EXISTS crops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                quantity REAL NOT NULL CHECK(quantity > 0),
                harvest_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Growing',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # Migration for existing databases
        columns = [
            row[1] for row in db.execute(
                "PRAGMA table_info(crops)"
            ).fetchall()
        ]

        if "user_id" not in columns:
            db.execute(
                "ALTER TABLE crops ADD COLUMN user_id INTEGER"
            )

        # Listings table
        db.execute("""
            CREATE TABLE IF NOT EXISTS listings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                crop TEXT NOT NULL,
                variety TEXT,
                quantity REAL NOT NULL CHECK(quantity > 0),
                unit TEXT NOT NULL,
                price REAL NOT NULL CHECK(price > 0),
                grade TEXT NOT NULL,
                village TEXT,
                district TEXT,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'Published',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

    yield


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="Mandi Mitra AI API",
    version="0.2.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


# --------------------------------------------------
# PYDANTIC MODELS
# --------------------------------------------------

class CropIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    quantity: float = Field(gt=0)
    date: str
    status: str = "Growing"


class CropUpdate(BaseModel):
    name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=80
    )
    quantity: Optional[float] = Field(default=None, gt=0)
    date: Optional[str] = None
    status: Optional[str] = None


class ListingIn(BaseModel):
    crop: str = Field(min_length=1, max_length=80)
    variety: str = ""
    quantity: float = Field(gt=0)
    unit: str = "Quintals"
    price: float = Field(gt=0)
    grade: str = "A"
    village: str = ""
    district: str = ""
    description: str = ""


class ListingUpdate(BaseModel):
    status: Optional[str] = None
    price: Optional[float] = Field(default=None, gt=0)
    quantity: Optional[float] = Field(default=None, gt=0)


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)
    role: str = "farmer"
    village: str = ""
    district: str = ""


class LoginIn(BaseModel):
    email: str
    password: str


# --------------------------------------------------
# DATABASE HELPER
# --------------------------------------------------

def rows(query: str, params=()):

    with sqlite3.connect(DB_PATH) as db:

        db.row_factory = sqlite3.Row

        result = db.execute(
            query,
            params
        ).fetchall()

        return [dict(row) for row in result]


# --------------------------------------------------
# PASSWORD SECURITY
# --------------------------------------------------

def _password_hash(password: str) -> str:

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        310000
    )

    return base64.b64encode(
        salt + digest
    ).decode()


def _password_ok(password: str, stored: str) -> bool:

    try:

        raw = base64.b64decode(stored.encode())

        salt = raw[:16]
        expected = raw[16:]

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            310000
        )

        return hmac.compare_digest(
            actual,
            expected
        )

    except Exception:

        return False


# --------------------------------------------------
# TOKEN GENERATION
# --------------------------------------------------

def _make_token(user_id: int) -> str:

    secret = os.environ.get(
        "MANDI_MITRA_SECRET",
        "LOCAL-DEV-ONLY-change-this-before-deployment"
    ).encode()

    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": user_id,
            "exp": int(time.time()) + 86400
        }).encode()
    ).decode().rstrip("=")

    signature = base64.urlsafe_b64encode(
        hmac.new(
            secret,
            payload.encode(),
            hashlib.sha256
        ).digest()
    ).decode().rstrip("=")

    return payload + "." + signature


# --------------------------------------------------
# AUTHENTICATION CHECK
# --------------------------------------------------

def _current_user(authorization: Optional[str]):

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Please log in first"
        )

    token = authorization.split(" ", 1)[1].strip()

    try:

        payload, signature = token.split(".", 1)

        secret = os.environ.get(
            "MANDI_MITRA_SECRET",
            "LOCAL-DEV-ONLY-change-this-before-deployment"
        ).encode()

        expected = base64.urlsafe_b64encode(
            hmac.new(
                secret,
                payload.encode(),
                hashlib.sha256
            ).digest()
        ).decode().rstrip("=")

        if not hmac.compare_digest(signature, expected):
            raise ValueError()

        data = json.loads(
            base64.urlsafe_b64decode(
                payload + "=" * (-len(payload) % 4)
            )
        )

        if data["exp"] < time.time():
            raise ValueError()

        user = rows(
            """
            SELECT id, full_name, email, role, village, district, created_at
            FROM users
            WHERE id = ?
            """,
            (data["sub"],)
        )

        if not user:
            raise ValueError()

        return user[0]

    except Exception:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired login token"
        )


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.post("/api/auth/register", status_code=201)
def register_user(item: RegisterIn):

    email = item.email.strip().lower()

    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(
            status_code=422,
            detail="Enter a valid email address"
        )

    if item.role not in {"farmer", "buyer", "fpo"}:
        raise HTTPException(
            status_code=422,
            detail="Role must be farmer, buyer, or fpo"
        )

    try:

        with sqlite3.connect(DB_PATH) as db:

            cur = db.execute(
                """
                INSERT INTO users
                (full_name, email, password_hash, role, village, district)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    item.full_name.strip(),
                    email,
                    _password_hash(item.password),
                    item.role,
                    item.village.strip(),
                    item.district.strip()
                )
            )

            user_id = cur.lastrowid

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists"
        )

    user = rows(
        """
        SELECT id, full_name, email, role, village, district, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    )[0]

    return {
        "message": "Account created",
        "access_token": _make_token(user_id),
        "token_type": "bearer",
        "user": user
    }


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.post("/api/auth/login")
def login_user(item: LoginIn):

    found = rows(
        "SELECT id, password_hash FROM users WHERE email = ?",
        (item.email.strip().lower(),)
    )

    if not found or not _password_ok(
        item.password,
        found[0]["password_hash"]
    ):

        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )

    user_id = found[0]["id"]

    user = rows(
        """
        SELECT id, full_name, email, role, village, district, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    )[0]

    return {
        "access_token": _make_token(user_id),
        "token_type": "bearer",
        "user": user
    }


# --------------------------------------------------
# CURRENT USER PROFILE
# --------------------------------------------------

@app.get("/api/auth/me")
def get_my_profile(
    authorization: Optional[str] = Header(default=None)
):

    return _current_user(authorization)


# --------------------------------------------------
# GENERAL ROUTES
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "name": "Mandi Mitra AI API",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/api/health")
def health():

    return {
        "status": "ok",
        "database": "SQLite",
        "market_data_mode": "DEMO"
    }


@app.get("/api/markets")
def get_markets():

    return {
        "mode": "DEMO",
        "notice": "Illustrative sample prices only; not live mandi data.",
        "items": DEMO_MARKETS
    }


# ==================================================
# CROPS API — PROTECTED BY LOGIN
# ==================================================

# GET ALL CROPS BELONGING TO CURRENT USER

@app.get("/api/crops")
def get_crops(
    authorization: Optional[str] = Header(default=None)
):

    user = _current_user(authorization)

    return rows(
        """
        SELECT * FROM crops
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user["id"],)
    )


# ADD A NEW CROP

@app.post("/api/crops", status_code=201)
def create_crop(
    item: CropIn,
    authorization: Optional[str] = Header(default=None)
):

    user = _current_user(authorization)

    with sqlite3.connect(DB_PATH) as db:

        cur = db.execute(
            """
            INSERT INTO crops
            (user_id, name, quantity, harvest_date, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                item.name.strip(),
                item.quantity,
                item.date,
                item.status
            )
        )

        crop_id = cur.lastrowid

    return rows(
        "SELECT * FROM crops WHERE id = ? AND user_id = ?",
        (crop_id, user["id"])
    )[0]


# UPDATE A CROP

@app.patch("/api/crops/{crop_id}")
def update_crop(
    crop_id: int,
    item: CropUpdate,
    authorization: Optional[str] = Header(default=None)
):

    user = _current_user(authorization)

    data = item.model_dump(exclude_none=True)

    if not data:

        raise HTTPException(
            status_code=400,
            detail="No fields supplied"
        )

    allowed = {
        "name": "name",
        "quantity": "quantity",
        "date": "harvest_date",
        "status": "status"
    }

    fields = [
        (allowed[key], value)
        for key, value in data.items()
    ]

    with sqlite3.connect(DB_PATH) as db:

        cur = db.execute(
            f"""
            UPDATE crops
            SET {', '.join(key + '=?' for key, value in fields)}
            WHERE id = ? AND user_id = ?
            """,
            [value for key, value in fields] + [
                crop_id,
                user["id"]
            ]
        )

        if cur.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Crop not found"
            )

    return rows(
        "SELECT * FROM crops WHERE id = ? AND user_id = ?",
        (crop_id, user["id"])
    )[0]


# DELETE A CROP

@app.delete("/api/crops/{crop_id}")
def delete_crop(
    crop_id: int,
    authorization: Optional[str] = Header(default=None)
):

    user = _current_user(authorization)

    with sqlite3.connect(DB_PATH) as db:

        cur = db.execute(
            """
            DELETE FROM crops
            WHERE id = ? AND user_id = ?
            """,
            (crop_id, user["id"])
        )

        if cur.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Crop not found"
            )

    return {
        "deleted": True,
        "id": crop_id
    }


# ==================================================
# LISTINGS API
# NOTE: These routes are still public in this version.
# ==================================================

@app.get("/api/listings")
def get_listings():

    return rows(
        "SELECT * FROM listings ORDER BY id DESC"
    )


@app.post("/api/listings", status_code=201)
def create_listing(item: ListingIn):

    data = item.model_dump()

    with sqlite3.connect(DB_PATH) as db:

        cur = db.execute(
            """
            INSERT INTO listings
            (
                crop, variety, quantity, unit,
                price, grade, village, district, description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(data.values())
        )

        listing_id = cur.lastrowid

    return rows(
        "SELECT * FROM listings WHERE id = ?",
        (listing_id,)
    )[0]


@app.patch("/api/listings/{listing_id}")
def update_listing(
    listing_id: int,
    item: ListingUpdate
):

    data = item.model_dump(exclude_none=True)

    if not data:

        raise HTTPException(
            status_code=400,
            detail="No fields supplied"
        )

    with sqlite3.connect(DB_PATH) as db:

        cur = db.execute(
            f"""
            UPDATE listings
            SET {', '.join(key + '=?' for key in data)}
            WHERE id = ?
            """,
            list(data.values()) + [listing_id]
        )

        if cur.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Listing not found"
            )

    return rows(
        "SELECT * FROM listings WHERE id = ?",
        (listing_id,)
    )[0]


@app.delete("/api/listings/{listing_id}")
def delete_listing(listing_id: int):

    with sqlite3.connect(DB_PATH) as db:

        cur = db.execute(
            "DELETE FROM listings WHERE id = ?",
            (listing_id,)
        )

        if cur.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Listing not found"
            )

    return {
        "deleted": True,
        "id": listing_id
    }