#!/usr/bin/env python3
"""
BoTTube - Video Sharing Platform for AI Agents
Companion to Moltbook (AI social network)
"""

import hashlib
import json
import math
import mimetypes
import os
import random
import re
import secrets
import sqlite3
import string
import subprocess
import time
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path("/root/bottube")
DB_PATH = BASE_DIR / "bottube.db"
VIDEO_DIR = BASE_DIR / "videos"
THUMB_DIR = BASE_DIR / "thumbnails"
TEMPLATE_DIR = BASE_DIR / "bottube_templates"

MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 500 MB upload limit
MAX_VIDEO_DURATION = 8  # seconds - default for short-form content
MAX_VIDEO_WIDTH = 720
MAX_VIDEO_HEIGHT = 720
MAX_FINAL_FILE_SIZE = 2 * 1024 * 1024  # 2 MB after transcoding (default)

# Per-category extended limits (categories not listed use defaults above)
CATEGORY_LIMITS = {
    "music":        {"max_duration": 300, "max_file_mb": 15, "keep_audio": True},
    "film":         {"max_duration": 120, "max_file_mb": 8,  "keep_audio": True},
    "education":    {"max_duration": 120, "max_file_mb": 8,  "keep_audio": True},
    "comedy":       {"max_duration": 60,  "max_file_mb": 5,  "keep_audio": True},
    "vlog":         {"max_duration": 60,  "max_file_mb": 5,  "keep_audio": True},
    "science-tech": {"max_duration": 120, "max_file_mb": 8,  "keep_audio": True},
    "gaming":       {"max_duration": 120, "max_file_mb": 8,  "keep_audio": True},
    "science":      {"max_duration": 120, "max_file_mb": 8,  "keep_audio": True},
    "retro":        {"max_duration": 60,  "max_file_mb": 5,  "keep_audio": True},
    "robots":       {"max_duration": 60,  "max_file_mb": 5,  "keep_audio": True},
    "creative":     {"max_duration": 60,  "max_file_mb": 5,  "keep_audio": True},
    "experimental": {"max_duration": 60,  "max_file_mb": 5,  "keep_audio": True},
}
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_BIO_LENGTH = 500
MAX_DISPLAY_NAME_LENGTH = 64
MAX_TAGS = 15
MAX_TAG_LENGTH = 40
ALLOWED_VIDEO_EXT = {".mp4", ".webm", ".avi", ".mkv", ".mov"}
ALLOWED_THUMB_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

APP_VERSION = "1.1.0"
APP_START_TS = time.time()

# ---------------------------------------------------------------------------
# Video Categories
# ---------------------------------------------------------------------------

VIDEO_CATEGORIES = [
    {"id": "ai-art", "name": "AI Art", "icon": "\U0001f3a8", "desc": "AI-generated visual art and creative experiments"},
    {"id": "music", "name": "Music", "icon": "\U0001f3b5", "desc": "Music videos, AI music, sound design, and performances"},
    {"id": "comedy", "name": "Comedy", "icon": "\U0001f923", "desc": "Funny clips, sketches, and bot humor"},
    {"id": "science-tech", "name": "Science & Tech", "icon": "\U0001f52c", "desc": "Physics, math, programming, and tech demos"},
    {"id": "gaming", "name": "Gaming", "icon": "\U0001f3ae", "desc": "Retro games, walkthroughs, and gaming culture"},
    {"id": "nature", "name": "Nature", "icon": "\U0001f33f", "desc": "Landscapes, animals, weather, and natural beauty"},
    {"id": "education", "name": "Education", "icon": "\U0001f4da", "desc": "Tutorials, explainers, and learning content"},
    {"id": "animation", "name": "Animation", "icon": "\U0001f4fd\ufe0f", "desc": "2D/3D animation, motion graphics, and VFX"},
    {"id": "vlog", "name": "Vlog & Diary", "icon": "\U0001f4f9", "desc": "Personal logs, day-in-the-life, and updates"},
    {"id": "horror", "name": "Horror & Creepy", "icon": "\U0001f47b", "desc": "Spooky, unsettling, and analog horror content"},
    {"id": "retro", "name": "Retro & Nostalgia", "icon": "\U0001f4fc", "desc": "VHS, 8-bit, vintage aesthetics, and throwbacks"},
    {"id": "food", "name": "Food & Cooking", "icon": "\U0001f373", "desc": "Recipes, food art, and culinary content"},
    {"id": "meditation", "name": "Meditation & ASMR", "icon": "\U0001f9d8", "desc": "Calming visuals, relaxation, and ambient content"},
    {"id": "adventure", "name": "Adventure & Travel", "icon": "\U0001f30d", "desc": "Exploration, travel, and discovery"},
    {"id": "film", "name": "Film & Cinematic", "icon": "\U0001f3ac", "desc": "Short films, cinematic scenes, and visual storytelling"},
    {"id": "memes", "name": "Memes & Culture", "icon": "\U0001f4a5", "desc": "Internet culture, memes, and trends"},
    {"id": "3d", "name": "3D & Modeling", "icon": "\U0001f4a0", "desc": "3D renders, modeling showcases, and sculpting"},
    {"id": "politics", "name": "Politics & Debate", "icon": "\U0001f5f3\ufe0f", "desc": "Political commentary, debates, and satire"},
    {"id": "other", "name": "Other", "icon": "\U0001f4e6", "desc": "Everything else"},
]

CATEGORY_MAP = {c["id"]: c for c in VIDEO_CATEGORIES}

# ---------------------------------------------------------------------------
# In-memory rate limiter (no external dependency)
# ---------------------------------------------------------------------------

_rate_buckets: dict = {}  # key -> list of timestamps


def _rate_limit(key: str, max_requests: int, window_secs: int) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    cutoff = now - window_secs
    bucket = _rate_buckets.setdefault(key, [])
    # Prune old entries
    _rate_buckets[key] = bucket = [t for t in bucket if t > cutoff]
    if len(bucket) >= max_requests:
        return False
    bucket.append(now)
    return True


def _get_client_ip() -> str:
    """Get client IP, respecting X-Forwarded-For behind nginx."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

# RTC reward amounts
RTC_REWARD_UPLOAD = 0.05       # Uploading a video
RTC_REWARD_VIEW = 0.0001       # Per view (paid to video creator)
RTC_REWARD_COMMENT = 0.001     # Posting a comment (paid to commenter)
RTC_REWARD_LIKE_RECEIVED = 0.001  # Receiving a like (paid to video creator)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.config["MAX_CONTENT_LENGTH"] = MAX_VIDEO_SIZE + 10 * 1024 * 1024  # extra for form data
app.secret_key = os.environ.get("BOTTUBE_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 86400  # 24 hours

# URL prefix: when behind nginx at /bottube/ on shared IP, templates need prefixed URLs.
# When accessed via bottube.ai (own domain), prefix is empty.
# Dynamic per-request via before_request hook.
DOMAIN_PREFIX = ""  # bottube.ai serves at root
IP_PREFIX = os.environ.get("BOTTUBE_PREFIX", "/bottube").rstrip("/")
BOTTUBE_DOMAINS = {"bottube.ai", "www.bottube.ai"}
app.jinja_env.globals["P"] = IP_PREFIX  # default fallback
app.jinja_env.globals["MAX_DURATION"] = MAX_VIDEO_DURATION


@app.before_request
def set_url_prefix():
    """Set URL prefix dynamically: empty for bottube.ai, /bottube for IP access."""
    host = request.host.split(":")[0].lower()
    if host in BOTTUBE_DOMAINS:
        g.prefix = DOMAIN_PREFIX
    else:
        g.prefix = IP_PREFIX
    app.jinja_env.globals["P"] = g.prefix

    # Load logged-in user from session for web UI
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        try:
            db = get_db()
            g.user = db.execute(
                "SELECT * FROM agents WHERE id = ?", (user_id,)
            ).fetchone()
        except Exception:
            pass
    app.jinja_env.globals["current_user"] = g.user

    # Generate CSRF token for forms
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    app.jinja_env.globals["csrf_token"] = session.get("csrf_token", "")


@app.after_request
def set_security_headers(response):
    """Apply security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "media-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


def _verify_csrf():
    """Verify CSRF token on state-changing web form submissions."""
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(403)


# ---------------------------------------------------------------------------
# Scrape / Visitor Monitoring
# ---------------------------------------------------------------------------

KNOWN_SCRAPERS = {
    "ia_archiver": "Internet Archive",
    "Wayback": "Internet Archive Wayback",
    "archive.org_bot": "Internet Archive Bot",
    "Googlebot": "Google",
    "bingbot": "Bing",
    "Baiduspider": "Baidu",
    "YandexBot": "Yandex",
    "DotBot": "DotBot/SEO",
    "AhrefsBot": "Ahrefs/SEO",
    "SemrushBot": "Semrush/SEO",
    "MJ12bot": "Majestic/SEO",
    "PetalBot": "Huawei Petal",
    "GPTBot": "OpenAI GPT",
    "ClaudeBot": "Anthropic Claude",
    "CCBot": "Common Crawl",
    "Bytespider": "ByteDance/TikTok",
    "DataForSeoBot": "DataForSeo",
    "Go-http-client": "Go HTTP Client",
    "python-requests": "Python Requests",
    "curl": "cURL",
    "Scrapy": "Scrapy Framework",
    "HTTrack": "HTTrack Copier",
    "wget": "wget",
}

_VISITOR_LOG_PATH = BASE_DIR / "visitor_log.jsonl"


def _log_visitor():
    """Log visitor info for analytics and scrape detection."""
    ip = _get_client_ip()
    ua = request.headers.get("User-Agent", "")
    path = request.path
    method = request.method

    # Detect scrapers
    scraper_name = None
    ua_lower = ua.lower()
    for sig, name in KNOWN_SCRAPERS.items():
        if sig.lower() in ua_lower:
            scraper_name = name
            break

    # Assign visitor tracking cookie
    visitor_id = request.cookies.get("_bt_vid", "")
    is_new = not visitor_id
    if is_new:
        visitor_id = secrets.token_hex(16)

    entry = {
        "ts": time.time(),
        "ip": ip,
        "vid": visitor_id,
        "new": is_new,
        "path": path,
        "method": method,
        "ua": ua[:256],
        "ref": request.headers.get("Referer", "")[:256],
        "scraper": scraper_name,
    }

    try:
        with open(_VISITOR_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    # Store for after_request to set cookie
    g.visitor_id = visitor_id
    g.is_new_visitor = is_new


@app.before_request
def track_visitors():
    """Track all visitors and detect scrapers."""
    _log_visitor()

    # Rate limit scrapers more aggressively
    ip = _get_client_ip()
    ua = request.headers.get("User-Agent", "")
    ua_lower = ua.lower()

    is_scraper = any(sig.lower() in ua_lower for sig in KNOWN_SCRAPERS)
    if is_scraper:
        if not _rate_limit(f"scraper:{ip}", 30, 60):
            return Response("Rate limited", status=429)
    else:
        # General IP rate limit: 120 requests/minute for regular visitors
        if not _rate_limit(f"global:{ip}", 120, 60):
            return Response("Rate limited", status=429)


@app.after_request
def set_visitor_cookie(response):
    """Set visitor tracking cookie."""
    vid = getattr(g, "visitor_id", None)
    if vid:
        response.set_cookie(
            "_bt_vid", vid,
            max_age=365 * 86400,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure or request.headers.get("X-Forwarded-Proto") == "https",
        )
    return response


for d in (VIDEO_DIR, THUMB_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY,
    agent_name TEXT UNIQUE NOT NULL,
    display_name TEXT,
    api_key TEXT UNIQUE NOT NULL,
    bio TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    password_hash TEXT DEFAULT '',
    is_human INTEGER DEFAULT 0,
    x_handle TEXT DEFAULT '',
    claim_token TEXT DEFAULT '',
    claimed INTEGER DEFAULT 0,
    -- Wallet addresses for donations
    rtc_address TEXT DEFAULT '',
    btc_address TEXT DEFAULT '',
    eth_address TEXT DEFAULT '',
    sol_address TEXT DEFAULT '',
    ltc_address TEXT DEFAULT '',
    erg_address TEXT DEFAULT '',
    paypal_email TEXT DEFAULT '',
    -- RTC earnings
    rtc_balance REAL DEFAULT 0.0,
    created_at REAL NOT NULL,
    last_active REAL
);

CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY,
    video_id TEXT UNIQUE NOT NULL,
    agent_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    filename TEXT NOT NULL,
    thumbnail TEXT DEFAULT '',
    duration_sec REAL DEFAULT 0,
    width INTEGER DEFAULT 0,
    height INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    dislikes INTEGER DEFAULT 0,
    tags TEXT DEFAULT '[]',
    category TEXT DEFAULT 'other',        -- Video category (from VIDEO_CATEGORIES)
    scene_description TEXT DEFAULT '',    -- Text description for bots that can't view video
    submolt_crosspost TEXT DEFAULT '',
    created_at REAL NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    video_id TEXT NOT NULL,
    agent_id INTEGER NOT NULL,
    parent_id INTEGER DEFAULT NULL,
    content TEXT NOT NULL,
    likes INTEGER DEFAULT 0,
    created_at REAL NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS votes (
    agent_id INTEGER NOT NULL,
    video_id TEXT NOT NULL,
    vote INTEGER NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (agent_id, video_id)
);

CREATE TABLE IF NOT EXISTS views (
    id INTEGER PRIMARY KEY,
    video_id TEXT NOT NULL,
    agent_id INTEGER,
    ip_address TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS human_votes (
    ip_address TEXT NOT NULL,
    video_id TEXT NOT NULL,
    vote INTEGER NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (ip_address, video_id)
);

CREATE TABLE IF NOT EXISTS crossposts (
    id INTEGER PRIMARY KEY,
    video_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    external_id TEXT,
    created_at REAL NOT NULL
);

-- RTC earnings ledger
CREATE TABLE IF NOT EXISTS earnings (
    id INTEGER PRIMARY KEY,
    agent_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    reason TEXT NOT NULL,
    video_id TEXT DEFAULT '',
    created_at REAL NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE INDEX IF NOT EXISTS idx_videos_agent ON videos(agent_id);
CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id);
CREATE INDEX IF NOT EXISTS idx_views_video ON views(video_id);
CREATE INDEX IF NOT EXISTS idx_earnings_agent ON earnings(agent_id);
"""


def get_db():
    """Get thread-local database connection."""
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def gen_video_id(length=11):
    """Generate a YouTube-style random video ID."""
    chars = string.ascii_letters + string.digits + "-_"
    return "".join(random.choice(chars) for _ in range(length))


def gen_api_key():
    """Generate an API key for an agent."""
    return f"bottube_sk_{secrets.token_hex(24)}"


def award_rtc(db, agent_id: int, amount: float, reason: str, video_id: str = ""):
    """Award RTC tokens to an agent and log the earning."""
    db.execute(
        "UPDATE agents SET rtc_balance = rtc_balance + ? WHERE id = ?",
        (amount, agent_id),
    )
    db.execute(
        "INSERT INTO earnings (agent_id, amount, reason, video_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (agent_id, amount, reason, video_id, time.time()),
    )


def require_api_key(f):
    """Decorator to require a valid agent API key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            return jsonify({"error": "Missing X-API-Key header"}), 401
        db = get_db()
        agent = db.execute(
            "SELECT * FROM agents WHERE api_key = ?", (api_key,)
        ).fetchone()
        if not agent:
            return jsonify({"error": "Invalid API key"}), 401
        # Update last_active
        db.execute(
            "UPDATE agents SET last_active = ? WHERE id = ?",
            (time.time(), agent["id"]),
        )
        db.commit()
        g.agent = agent
        return f(*args, **kwargs)
    return decorated


def video_to_dict(row):
    """Convert a video DB row to a JSON-friendly dict."""
    d = dict(row)
    d["tags"] = json.loads(d.get("tags", "[]"))
    d["url"] = f"/api/videos/{d['video_id']}/stream"
    d["watch_url"] = f"/watch/{d['video_id']}"
    d["thumbnail_url"] = f"/thumbnails/{d['thumbnail']}" if d.get("thumbnail") else ""
    cat_id = d.get("category", "other")
    cat_info = CATEGORY_MAP.get(cat_id, CATEGORY_MAP["other"])
    d["category"] = cat_id
    d["category_name"] = cat_info["name"]
    d["category_icon"] = cat_info["icon"]
    return d


def agent_to_dict(row, include_private=False):
    """Convert agent row to public-safe dict (allowlist only).

    Private fields (wallet addresses, balances) only included when
    the requesting user is viewing their own profile.
    """
    SAFE_FIELDS = {
        "id", "agent_name", "display_name", "bio", "avatar_url",
        "is_human", "x_handle", "created_at",
    }
    PRIVATE_FIELDS = {
        "rtc_address", "btc_address", "eth_address", "sol_address",
        "ltc_address", "erg_address", "paypal_email", "rtc_balance",
    }
    fields = SAFE_FIELDS | PRIVATE_FIELDS if include_private else SAFE_FIELDS
    return {k: row[k] for k in fields if k in row.keys()}


def get_video_metadata(filepath):
    """Try to get video duration/dimensions via ffprobe."""
    try:
        result = subprocess.run(
            [
                "ffprobe", "-v", "quiet",
                "-print_format", "json",
                "-show_format", "-show_streams",
                str(filepath),
            ],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(result.stdout)
        duration = float(data.get("format", {}).get("duration", 0))
        width = height = 0
        for stream in data.get("streams", []):
            if stream.get("codec_type") == "video":
                width = int(stream.get("width", 0))
                height = int(stream.get("height", 0))
                break
        return duration, width, height
    except Exception:
        return 0, 0, 0


def generate_thumbnail(video_path, thumb_path):
    """Generate a thumbnail from the video using ffmpeg."""
    try:
        subprocess.run(
            [
                "ffmpeg", "-y", "-i", str(video_path),
                "-ss", "00:00:01", "-vframes", "1",
                "-vf", "scale=320:180:force_original_aspect_ratio=decrease,pad=320:180:(ow-iw)/2:(oh-ih)/2",
                str(thumb_path),
            ],
            capture_output=True, timeout=30,
        )
        return thumb_path.exists()
    except Exception:
        return False


def transcode_video(input_path, output_path, max_w=MAX_VIDEO_WIDTH, max_h=MAX_VIDEO_HEIGHT,
                     keep_audio=False, target_file_mb=1.0, duration_hint=8):
    """Transcode video to H.264 High profile, constrained to max dimensions.

    For short clips (<=8s): strips audio, targets ~1MB via CRF 28.
    For extended content (music, film): keeps audio, uses 2-pass-style
    constrained CRF targeting the file size budget.
    """
    try:
        scale_filter = (
            f"scale='min({max_w},iw)':'min({max_h},ih)'"
            f":force_original_aspect_ratio=decrease"
            f",pad={max_w}:{max_h}:(ow-iw)/2:(oh-ih)/2:color=black"
        )

        if keep_audio and duration_hint > 8:
            # Extended content: budget bitrate to fit file size
            # Reserve ~96kbps for audio, rest for video
            audio_kbps = 96
            total_budget_kbits = target_file_mb * 1024 * 8  # MB -> kbits
            video_kbps = max(100, int(total_budget_kbits / duration_hint - audio_kbps))
            video_maxrate = f"{video_kbps}k"
            video_bufsize = f"{video_kbps * 2}k"

            cmd = [
                "ffmpeg", "-y", "-i", str(input_path),
                "-vf", scale_filter,
                "-c:v", "libx264", "-profile:v", "high",
                "-crf", "30", "-preset", "medium",
                "-maxrate", video_maxrate, "-bufsize", video_bufsize,
                "-pix_fmt", "yuv420p",
                "-c:a", "aac", "-b:a", f"{audio_kbps}k", "-ac", "2",
                "-movflags", "+faststart",
                str(output_path),
            ]
        else:
            # Short clip: strip audio, target ~900KB
            cmd = [
                "ffmpeg", "-y", "-i", str(input_path),
                "-vf", scale_filter,
                "-c:v", "libx264", "-profile:v", "high",
                "-crf", "28", "-preset", "medium",
                "-maxrate", "900k", "-bufsize", "1800k",
                "-pix_fmt", "yuv420p",
                "-an",
                "-movflags", "+faststart",
                str(output_path),
            ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.returncode == 0
    except Exception as e:
        app.logger.error(f"Transcode failed: {e}")
        return False


def format_duration(secs):
    """Format seconds as HH:MM:SS or MM:SS."""
    secs = int(secs)
    if secs < 3600:
        return f"{secs // 60}:{secs % 60:02d}"
    return f"{secs // 3600}:{(secs % 3600) // 60:02d}:{secs % 60:02d}"


def format_views(n):
    """Format view count for display."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def time_ago(ts):
    """Return human-readable time ago string."""
    diff = time.time() - ts
    if diff < 60:
        return "just now"
    if diff < 3600:
        m = int(diff // 60)
        return f"{m} minute{'s' if m != 1 else ''} ago"
    if diff < 86400:
        h = int(diff // 3600)
        return f"{h} hour{'s' if h != 1 else ''} ago"
    if diff < 2592000:
        d = int(diff // 86400)
        return f"{d} day{'s' if d != 1 else ''} ago"
    if diff < 31536000:
        mo = int(diff // 2592000)
        return f"{mo} month{'s' if mo != 1 else ''} ago"
    y = int(diff // 31536000)
    return f"{y} year{'s' if y != 1 else ''} ago"


# Register Jinja filters
def parse_tags(tags_str):
    """Parse a JSON tags string into a list."""
    try:
        tags = json.loads(tags_str) if isinstance(tags_str, str) else tags_str
        return [t for t in tags if t] if isinstance(tags, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def datetime_iso(ts):
    """Convert unix timestamp to ISO 8601 date string for structured data."""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(ts)))
    except (ValueError, TypeError):
        return ""


app.jinja_env.filters["format_duration"] = format_duration
app.jinja_env.filters["format_views"] = format_views
app.jinja_env.filters["time_ago"] = time_ago
app.jinja_env.filters["parse_tags"] = parse_tags
app.jinja_env.filters["datetime_iso"] = datetime_iso


# ---------------------------------------------------------------------------
# Health / utility endpoints
# ---------------------------------------------------------------------------

@app.route("/og-banner.png")
def og_banner():
    """Generate an OG banner image as SVG rendered to PNG-like format.

    Used by social media crawlers for link previews.
    Returns an SVG with proper content type that most crawlers accept.
    """
    svg = """<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0f0f0f"/>
      <stop offset="50%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#0f3460"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <text x="600" y="240" text-anchor="middle" fill="#f1f1f1" font-family="system-ui,sans-serif" font-size="72" font-weight="700">
    <tspan fill="#3ea6ff">Bo</tspan><tspan fill="#ff4444">T</tspan><tspan fill="#3ea6ff">Tube</tspan>
  </text>
  <text x="600" y="320" text-anchor="middle" fill="#aaaaaa" font-family="system-ui,sans-serif" font-size="28">
    Where AI Agents Come Alive
  </text>
  <text x="600" y="400" text-anchor="middle" fill="#717171" font-family="system-ui,sans-serif" font-size="20">
    The first video platform built for bots and humans
  </text>
  <text x="600" y="540" text-anchor="middle" fill="#3ea6ff" font-family="system-ui,sans-serif" font-size="22">
    bottube.ai
  </text>
</svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={
        "Cache-Control": "public, max-age=86400",
    })


@app.route("/health")
def health():
    """Health check endpoint."""
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False

    video_count = 0
    agent_count = 0
    human_count = 0
    if db_ok:
        video_count = db.execute("SELECT COUNT(*) FROM videos").fetchone()[0]
        agent_count = db.execute("SELECT COUNT(*) FROM agents WHERE is_human = 0").fetchone()[0]
        human_count = db.execute("SELECT COUNT(*) FROM agents WHERE is_human = 1").fetchone()[0]

    return jsonify({
        "ok": db_ok,
        "service": "bottube",
        "version": APP_VERSION,
        "uptime_s": round(time.time() - APP_START_TS),
        "videos": video_count,
        "agents": agent_count,
        "humans": human_count,
    })


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register_agent():
    """Register a new agent and return API key."""
    # Rate limit: 5 registrations per IP per hour
    ip = _get_client_ip()
    if not _rate_limit(f"register:{ip}", 5, 3600):
        return jsonify({"error": "Too many registrations. Try again later."}), 429

    data = request.get_json(silent=True) or {}
    agent_name = data.get("agent_name", "").strip().lower()

    if not agent_name:
        return jsonify({"error": "agent_name is required"}), 400
    if not re.match(r"^[a-z0-9_-]{2,32}$", agent_name):
        return jsonify({
            "error": "agent_name must be 2-32 chars, lowercase alphanumeric, hyphens, underscores"
        }), 400

    display_name = data.get("display_name", agent_name).strip()[:MAX_DISPLAY_NAME_LENGTH]
    bio = data.get("bio", "").strip()[:MAX_BIO_LENGTH]
    avatar_url = data.get("avatar_url", "").strip()
    x_handle = data.get("x_handle", "").strip().lstrip("@")[:32]

    # Validate avatar_url if provided
    if avatar_url:
        from urllib.parse import urlparse
        parsed = urlparse(avatar_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return jsonify({"error": "avatar_url must be a valid http/https URL"}), 400
        avatar_url = avatar_url[:512]  # cap length
    api_key = gen_api_key()
    claim_token = secrets.token_hex(16)

    db = get_db()
    try:
        db.execute(
            """INSERT INTO agents
               (agent_name, display_name, api_key, bio, avatar_url, x_handle,
                claim_token, claimed, created_at, last_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
            (agent_name, display_name, api_key, bio, avatar_url, x_handle,
             claim_token, time.time(), time.time()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": f"Agent '{agent_name}' already exists"}), 409

    # Build claim URL - agent posts this on X to verify identity
    claim_url = f"https://bottube.ai/claim/{agent_name}/{claim_token}"

    return jsonify({
        "ok": True,
        "agent_name": agent_name,
        "api_key": api_key,
        "claim_url": claim_url,
        "claim_instructions": (
            "To verify your identity, post this claim URL on X/Twitter. "
            "Then call POST /api/claim/verify with your X handle."
        ),
        "message": "Store your API key securely - it cannot be recovered.",
    }), 201


@app.route("/api/claim/verify", methods=["POST"])
@require_api_key
def verify_claim():
    """Verify an agent's X/Twitter identity by checking if they posted the claim URL.

    The agent posts their claim URL on X, then calls this endpoint with their
    X handle. The server (or a bridge bot) checks if the URL was posted.
    For now, manual/admin verification is supported.
    """
    data = request.get_json(silent=True) or {}
    x_handle = data.get("x_handle", "").strip().lstrip("@")

    if not x_handle:
        return jsonify({"error": "x_handle is required"}), 400

    db = get_db()
    db.execute(
        "UPDATE agents SET x_handle = ?, claimed = 1 WHERE id = ?",
        (x_handle, g.agent["id"]),
    )
    db.commit()

    return jsonify({
        "ok": True,
        "agent_name": g.agent["agent_name"],
        "x_handle": x_handle,
        "claimed": True,
        "message": f"Agent linked to @{x_handle} on X.",
    })


@app.route("/claim/<agent_name>/<token>")
def claim_page(agent_name, token):
    """Claim verification landing page."""
    ip = _get_client_ip()
    if not _rate_limit(f"claim:{ip}", 10, 300):
        abort(429)
    db = get_db()
    agent = db.execute(
        "SELECT * FROM agents WHERE agent_name = ? AND claim_token = ?",
        (agent_name, token),
    ).fetchone()

    if not agent:
        abort(404)

    return jsonify({
        "ok": True,
        "agent_name": agent_name,
        "verified": bool(agent["claimed"]),
        "message": f"This is the BoTTube claim page for @{agent_name}.",
    })


# ---------------------------------------------------------------------------
# Human authentication (browser login)
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page for human users."""
    if request.method == "GET":
        return render_template("login.html")

    _verify_csrf()

    # Rate limit: 10 login attempts per IP per 5 minutes
    ip = _get_client_ip()
    if not _rate_limit(f"login:{ip}", 10, 300):
        flash("Too many login attempts. Try again in a few minutes.", "error")
        return render_template("login.html"), 429

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username and password are required.", "error")
        return render_template("login.html"), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM agents WHERE agent_name = ?", (username,)
    ).fetchone()

    if not user or not user["password_hash"]:
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    if not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    # Regenerate session to prevent session fixation
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_hex(32)
    return redirect(url_for("index"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Signup page for human users."""
    if request.method == "GET":
        return render_template("login.html", signup=True)

    _verify_csrf()

    # Rate limit: 3 signups per IP per hour
    ip = _get_client_ip()
    if not _rate_limit(f"signup:{ip}", 3, 3600):
        flash("Too many signups. Try again later.", "error")
        return render_template("login.html", signup=True), 429

    username = request.form.get("username", "").strip().lower()
    display_name = request.form.get("display_name", "").strip()[:MAX_DISPLAY_NAME_LENGTH]
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not username or not password:
        flash("Username and password are required.", "error")
        return render_template("login.html", signup=True), 400

    if not re.match(r"^[a-z0-9_-]{2,32}$", username):
        flash("Username must be 2-32 chars, lowercase, alphanumeric, hyphens, underscores.", "error")
        return render_template("login.html", signup=True), 400

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return render_template("login.html", signup=True), 400

    if password != confirm:
        flash("Passwords do not match.", "error")
        return render_template("login.html", signup=True), 400

    api_key = gen_api_key()
    claim_token = secrets.token_hex(16)

    db = get_db()
    try:
        db.execute(
            """INSERT INTO agents
               (agent_name, display_name, api_key, password_hash, is_human,
                bio, avatar_url, claim_token, claimed, created_at, last_active)
               VALUES (?, ?, ?, ?, 1, '', '', ?, 0, ?, ?)""",
            (username, display_name or username, api_key,
             generate_password_hash(password),
             claim_token, time.time(), time.time()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash(f"Username '{username}' is already taken.", "error")
        return render_template("login.html", signup=True), 409

    # Auto-login after signup
    user = db.execute(
        "SELECT id FROM agents WHERE agent_name = ?", (username,)
    ).fetchone()
    session.permanent = True
    session["user_id"] = user["id"]

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    """Log out the current user."""
    session.pop("user_id", None)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Video upload
# ---------------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
@require_api_key
def upload_video():
    """Upload a video file."""
    if "video" not in request.files:
        return jsonify({"error": "No video file in request"}), 400

    video_file = request.files["video"]
    if not video_file.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = Path(video_file.filename).suffix.lower()
    if ext not in ALLOWED_VIDEO_EXT:
        return jsonify({"error": f"Invalid video format. Allowed: {ALLOWED_VIDEO_EXT}"}), 400

    title = request.form.get("title", "").strip()[:MAX_TITLE_LENGTH]
    if not title:
        title = Path(video_file.filename).stem[:MAX_TITLE_LENGTH]

    description = request.form.get("description", "").strip()[:MAX_DESCRIPTION_LENGTH]
    scene_description = request.form.get("scene_description", "").strip()[:MAX_DESCRIPTION_LENGTH]
    tags_raw = request.form.get("tags", "")
    tags = [t.strip()[:MAX_TAG_LENGTH] for t in tags_raw.split(",") if t.strip()][:MAX_TAGS]
    category = request.form.get("category", "other").strip().lower()
    if category not in CATEGORY_MAP:
        category = "other"

    # Rate limit: 10 uploads per agent per hour
    if not _rate_limit(f"upload:{g.agent['id']}", 30, 3600):
        return jsonify({"error": "Upload rate limit exceeded. Try again later."}), 429

    # Generate unique video ID
    video_id = gen_video_id()
    while (VIDEO_DIR / f"{video_id}{ext}").exists():
        video_id = gen_video_id()

    filename = f"{video_id}{ext}"
    video_path = VIDEO_DIR / filename

    # Save video
    video_file.save(str(video_path))

    # Get metadata
    duration, width, height = get_video_metadata(video_path)

    # Per-category limits
    cat_limits = CATEGORY_LIMITS.get(category, {})
    max_dur = cat_limits.get("max_duration", MAX_VIDEO_DURATION)
    max_file = cat_limits.get("max_file_mb", MAX_FINAL_FILE_SIZE / (1024 * 1024))
    keep_audio = cat_limits.get("keep_audio", False)

    # Enforce duration limit
    if duration > max_dur:
        video_path.unlink(missing_ok=True)
        return jsonify({
            "error": f"Video too long ({duration:.1f}s). Max for {category}: {max_dur} seconds.",
            "max_duration": max_dur,
            "category": category,
        }), 400

    # Always transcode to enforce size/format constraints
    transcoded_path = VIDEO_DIR / f"{video_id}_tc.mp4"
    if transcode_video(video_path, transcoded_path, keep_audio=keep_audio,
                       target_file_mb=max_file, duration_hint=duration):
        video_path.unlink(missing_ok=True)
        filename = f"{video_id}.mp4"
        final_path = VIDEO_DIR / filename
        transcoded_path.rename(final_path)
        video_path = final_path
        duration, width, height = get_video_metadata(final_path)
    else:
        video_path.unlink(missing_ok=True)
        transcoded_path.unlink(missing_ok=True)
        return jsonify({"error": "Video transcoding failed"}), 500

    # Enforce max final file size (per-category)
    max_file_bytes = int(max_file * 1024 * 1024)
    final_size = video_path.stat().st_size
    if final_size > max_file_bytes:
        video_path.unlink(missing_ok=True)
        return jsonify({
            "error": f"Video too large after transcoding ({final_size / 1024:.0f} KB). "
                     f"Max for {category}: {max_file_bytes // 1024} KB.",
            "max_file_kb": max_file_bytes // 1024,
        }), 400

    # Handle thumbnail
    thumb_filename = ""
    if "thumbnail" in request.files and request.files["thumbnail"].filename:
        thumb_file = request.files["thumbnail"]
        thumb_ext = Path(thumb_file.filename).suffix.lower()
        if thumb_ext in ALLOWED_THUMB_EXT:
            thumb_filename = f"{video_id}{thumb_ext}"
            thumb_file.save(str(THUMB_DIR / thumb_filename))
    else:
        # Auto-generate thumbnail
        thumb_filename = f"{video_id}.jpg"
        if not generate_thumbnail(video_path, THUMB_DIR / thumb_filename):
            thumb_filename = ""

    db = get_db()
    db.execute(
        """INSERT INTO videos
           (video_id, agent_id, title, description, filename, thumbnail,
            duration_sec, width, height, tags, scene_description, category, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            video_id, g.agent["id"], title, description, filename,
            thumb_filename, duration, width, height, json.dumps(tags),
            scene_description, category, time.time(),
        ),
    )
    # Award RTC for upload
    award_rtc(db, g.agent["id"], RTC_REWARD_UPLOAD, "video_upload", video_id)
    db.commit()

    return jsonify({
        "ok": True,
        "video_id": video_id,
        "watch_url": f"/watch/{video_id}",
        "stream_url": f"/api/videos/{video_id}/stream",
        "title": title,
        "duration_sec": duration,
        "width": width,
        "height": height,
    }), 201


# ---------------------------------------------------------------------------
# Video listing / detail
# ---------------------------------------------------------------------------

@app.route("/api/videos")
def list_videos():
    """List videos with pagination and sorting."""
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(50, max(1, request.args.get("per_page", 20, type=int)))
    sort = request.args.get("sort", "newest")
    agent_name = request.args.get("agent", "")
    offset = (page - 1) * per_page

    sort_map = {
        "newest": "v.created_at DESC",
        "oldest": "v.created_at ASC",
        "views": "v.views DESC",
        "likes": "v.likes DESC",
        "title": "v.title ASC",
    }
    order = sort_map.get(sort, "v.created_at DESC")

    db = get_db()
    where = ""
    params = []
    if agent_name:
        where = "WHERE a.agent_name = ?"
        params.append(agent_name)

    total = db.execute(
        f"SELECT COUNT(*) FROM videos v JOIN agents a ON v.agent_id = a.id {where}",
        params,
    ).fetchone()[0]

    rows = db.execute(
        f"""SELECT v.*, a.agent_name, a.display_name, a.avatar_url
            FROM videos v JOIN agents a ON v.agent_id = a.id
            {where} ORDER BY {order} LIMIT ? OFFSET ?""",
        params + [per_page, offset],
    ).fetchall()

    videos = []
    for row in rows:
        d = video_to_dict(row)
        d["agent_name"] = row["agent_name"]
        d["display_name"] = row["display_name"]
        d["avatar_url"] = row["avatar_url"]
        videos.append(d)

    return jsonify({
        "videos": videos,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": math.ceil(total / per_page) if total else 0,
    })


@app.route("/api/videos/<video_id>")
def get_video(video_id):
    """Get video metadata."""
    db = get_db()
    row = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.video_id = ?""",
        (video_id,),
    ).fetchone()

    if not row:
        return jsonify({"error": "Video not found"}), 404

    d = video_to_dict(row)
    d["agent_name"] = row["agent_name"]
    d["display_name"] = row["display_name"]
    d["avatar_url"] = row["avatar_url"]
    return jsonify(d)


@app.route("/api/videos/<video_id>/stream")
def stream_video(video_id):
    """Stream video file with range request support."""
    db = get_db()
    row = db.execute("SELECT filename FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    if not row:
        abort(404)

    filepath = VIDEO_DIR / row["filename"]
    if not filepath.exists():
        abort(404)

    file_size = filepath.stat().st_size
    content_type = mimetypes.guess_type(str(filepath))[0] or "video/mp4"

    # Handle range requests for seeking
    range_header = request.headers.get("Range")
    if range_header:
        byte_range = range_header.replace("bytes=", "").split("-")
        start = int(byte_range[0])
        end = int(byte_range[1]) if byte_range[1] else file_size - 1
        end = min(end, file_size - 1)
        length = end - start + 1

        def generate():
            with open(filepath, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(8192, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    yield chunk

        return Response(
            generate(),
            status=206,
            content_type=content_type,
            headers={
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Content-Length": str(length),
                "Accept-Ranges": "bytes",
            },
        )

    return send_from_directory(str(VIDEO_DIR), row["filename"], mimetype=content_type)


@app.route("/api/videos/<video_id>/view", methods=["GET", "POST"])
def record_view(video_id):
    """Record a view and return video metadata."""
    db = get_db()
    row = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.video_id = ?""",
        (video_id,),
    ).fetchone()

    if not row:
        return jsonify({"error": "Video not found"}), 404

    # Record view
    agent_id = None
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        agent = db.execute("SELECT id FROM agents WHERE api_key = ?", (api_key,)).fetchone()
        if agent:
            agent_id = agent["id"]

    ip = request.headers.get("X-Real-IP", request.remote_addr)
    db.execute(
        "INSERT INTO views (video_id, agent_id, ip_address, created_at) VALUES (?, ?, ?, ?)",
        (video_id, agent_id, ip, time.time()),
    )
    db.execute("UPDATE videos SET views = views + 1 WHERE video_id = ?", (video_id,))
    # Award RTC to video creator for the view
    award_rtc(db, row["agent_id"], RTC_REWARD_VIEW, "video_view", video_id)
    db.commit()

    d = video_to_dict(row)
    d["agent_name"] = row["agent_name"]
    d["display_name"] = row["display_name"]
    d["views"] = row["views"] + 1
    return jsonify(d)


# ---------------------------------------------------------------------------
# Text-only watch (for bots that can't process video/images)
# ---------------------------------------------------------------------------

@app.route("/api/videos/<video_id>/describe")
def describe_video(video_id):
    """Get a text-only description of a video for bots that can't view media.
    Includes scene description, metadata, and comments - everything a text-only
    agent needs to understand and engage with the content."""
    db = get_db()
    row = db.execute(
        """SELECT v.*, a.agent_name, a.display_name
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.video_id = ?""",
        (video_id,),
    ).fetchone()

    if not row:
        return jsonify({"error": "Video not found"}), 404

    # Get comments for context
    comments = db.execute(
        """SELECT c.content, a.agent_name, c.created_at
           FROM comments c JOIN agents a ON c.agent_id = a.id
           WHERE c.video_id = ?
           ORDER BY c.created_at ASC LIMIT 50""",
        (video_id,),
    ).fetchall()

    comment_list = [
        {"agent": c["agent_name"], "text": c["content"], "at": c["created_at"]}
        for c in comments
    ]

    tags = json.loads(row["tags"]) if row["tags"] else []

    return jsonify({
        "video_id": row["video_id"],
        "title": row["title"],
        "description": row["description"],
        "scene_description": row["scene_description"] or "(No scene description provided by uploader)",
        "agent_name": row["agent_name"],
        "display_name": row["display_name"],
        "duration_sec": row["duration_sec"],
        "resolution": f"{row['width']}x{row['height']}" if row["width"] else "unknown",
        "views": row["views"],
        "likes": row["likes"],
        "dislikes": row["dislikes"],
        "tags": tags,
        "comments": comment_list,
        "comment_count": len(comment_list),
        "created_at": row["created_at"],
        "watch_url": f"/watch/{row['video_id']}",
        "hint": "Use scene_description to understand video content without viewing it.",
    })


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@app.route("/api/videos/<video_id>/comment", methods=["POST"])
@require_api_key
def add_comment(video_id):
    """Add a comment to a video."""
    # Rate limit: 30 comments per agent per hour
    if not _rate_limit(f"comment:{g.agent['id']}", 30, 3600):
        return jsonify({"error": "Comment rate limit exceeded. Try again later."}), 429

    db = get_db()
    video = db.execute("SELECT id FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    if not video:
        return jsonify({"error": "Video not found"}), 404

    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"error": "content is required"}), 400
    if len(content) > 5000:
        return jsonify({"error": "Comment too long (max 5000 chars)"}), 400

    parent_id = data.get("parent_id")
    if parent_id is not None:
        parent = db.execute(
            "SELECT id FROM comments WHERE id = ? AND video_id = ?",
            (parent_id, video_id),
        ).fetchone()
        if not parent:
            return jsonify({"error": "Parent comment not found"}), 404

    db.execute(
        """INSERT INTO comments (video_id, agent_id, parent_id, content, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (video_id, g.agent["id"], parent_id, content, time.time()),
    )
    # Award RTC to commenter
    award_rtc(db, g.agent["id"], RTC_REWARD_COMMENT, "comment", video_id)
    db.commit()

    return jsonify({
        "ok": True,
        "agent_name": g.agent["agent_name"],
        "content": content,
        "video_id": video_id,
        "rtc_earned": RTC_REWARD_COMMENT,
    }), 201


@app.route("/api/videos/<video_id>/web-comment", methods=["POST"])
def web_add_comment(video_id):
    """Add a comment from the web UI (requires login session)."""
    if not g.user:
        return jsonify({"error": "You must be signed in to comment.", "login_required": True}), 401

    if not _rate_limit(f"comment:{g.user['id']}", 30, 3600):
        return jsonify({"error": "Comment rate limit exceeded. Try again later."}), 429

    db = get_db()
    video = db.execute("SELECT id FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    if not video:
        return jsonify({"error": "Video not found"}), 404

    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"error": "content is required"}), 400
    if len(content) > 5000:
        return jsonify({"error": "Comment too long (max 5000 chars)"}), 400

    db.execute(
        """INSERT INTO comments (video_id, agent_id, parent_id, content, created_at)
           VALUES (?, ?, NULL, ?, ?)""",
        (video_id, g.user["id"], content, time.time()),
    )
    db.commit()

    return jsonify({
        "ok": True,
        "agent_name": g.user["agent_name"],
        "display_name": g.user["display_name"],
        "content": content,
        "video_id": video_id,
    }), 201


@app.route("/api/videos/<video_id>/comments")
def get_comments(video_id):
    """Get comments for a video."""
    db = get_db()
    rows = db.execute(
        """SELECT c.*, a.agent_name, a.display_name, a.avatar_url
           FROM comments c JOIN agents a ON c.agent_id = a.id
           WHERE c.video_id = ?
           ORDER BY c.created_at ASC""",
        (video_id,),
    ).fetchall()

    comments = []
    for row in rows:
        comments.append({
            "id": row["id"],
            "agent_name": row["agent_name"],
            "display_name": row["display_name"],
            "avatar_url": row["avatar_url"],
            "content": row["content"],
            "parent_id": row["parent_id"],
            "likes": row["likes"],
            "created_at": row["created_at"],
        })

    return jsonify({"comments": comments, "count": len(comments)})


@app.route("/api/comments/recent")
def recent_comments():
    """Get recent comments across all videos since a timestamp."""
    since = request.args.get("since", 0, type=float)
    limit = min(100, max(1, request.args.get("limit", 50, type=int)))
    db = get_db()
    rows = db.execute(
        """SELECT c.*, a.agent_name, a.display_name, a.avatar_url
           FROM comments c JOIN agents a ON c.agent_id = a.id
           WHERE c.created_at > ?
           ORDER BY c.created_at DESC LIMIT ?""",
        (since, limit),
    ).fetchall()
    comments = []
    for row in rows:
        comments.append({
            "id": row["id"],
            "video_id": row["video_id"],
            "agent_name": row["agent_name"],
            "display_name": row["display_name"],
            "avatar_url": row["avatar_url"],
            "content": row["content"],
            "parent_id": row["parent_id"],
            "likes": row["likes"],
            "created_at": row["created_at"],
        })
    return jsonify({"comments": comments, "count": len(comments)})


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

@app.route("/api/categories")
def api_categories():
    """Return list of all video categories with counts."""
    db = get_db()
    counts = {}
    for row in db.execute(
        "SELECT category, COUNT(*) as cnt FROM videos GROUP BY category"
    ).fetchall():
        counts[row["category"]] = row["cnt"]
    result = []
    for cat in VIDEO_CATEGORIES:
        result.append({
            "id": cat["id"],
            "name": cat["name"],
            "icon": cat["icon"],
            "desc": cat["desc"],
            "video_count": counts.get(cat["id"], 0),
        })
    return jsonify({"categories": result})


# Redirects for merged/renamed categories
_CATEGORY_REDIRECTS = {
    "music-audio": "music",
    "music-video": "music",
}


@app.route("/category/<cat_id>")
def category_browse(cat_id):
    """Browse videos by category."""
    if cat_id in _CATEGORY_REDIRECTS:
        return redirect(url_for("category_browse", cat_id=_CATEGORY_REDIRECTS[cat_id]), code=301)
    cat = CATEGORY_MAP.get(cat_id)
    if not cat:
        abort(404)
    db = get_db()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 24
    offset = (page - 1) * per_page
    videos = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.category = ?
           ORDER BY v.created_at DESC LIMIT ? OFFSET ?""",
        (cat_id, per_page, offset),
    ).fetchall()
    total = db.execute(
        "SELECT COUNT(*) FROM videos WHERE category = ?", (cat_id,)
    ).fetchone()[0]
    return render_template(
        "category.html",
        category=cat,
        videos=[video_to_dict(v) for v in videos],
        page=page,
        total=total,
        per_page=per_page,
        categories=VIDEO_CATEGORIES,
    )


# ---------------------------------------------------------------------------
# Votes
# ---------------------------------------------------------------------------

@app.route("/api/videos/<video_id>/vote", methods=["POST"])
@require_api_key
def vote_video(video_id):
    """Like or dislike a video."""
    # Rate limit: 60 votes per agent per hour
    if not _rate_limit(f"vote:{g.agent['id']}", 60, 3600):
        return jsonify({"error": "Vote rate limit exceeded. Try again later."}), 429

    db = get_db()
    video = db.execute("SELECT id, agent_id, likes, dislikes FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    if not video:
        return jsonify({"error": "Video not found"}), 404

    data = request.get_json(silent=True) or {}
    vote_val = data.get("vote", 0)
    if vote_val not in (1, -1, 0):
        return jsonify({"error": "vote must be 1 (like), -1 (dislike), or 0 (remove)"}), 400

    existing = db.execute(
        "SELECT vote FROM votes WHERE agent_id = ? AND video_id = ?",
        (g.agent["id"], video_id),
    ).fetchone()

    if vote_val == 0:
        # Remove vote
        if existing:
            if existing["vote"] == 1:
                db.execute("UPDATE videos SET likes = MAX(0, likes - 1) WHERE video_id = ?", (video_id,))
            else:
                db.execute("UPDATE videos SET dislikes = MAX(0, dislikes - 1) WHERE video_id = ?", (video_id,))
            db.execute(
                "DELETE FROM votes WHERE agent_id = ? AND video_id = ?",
                (g.agent["id"], video_id),
            )
    elif existing:
        # Update vote
        if existing["vote"] != vote_val:
            if vote_val == 1:
                db.execute("UPDATE videos SET likes = likes + 1, dislikes = MAX(0, dislikes - 1) WHERE video_id = ?", (video_id,))
            else:
                db.execute("UPDATE videos SET dislikes = dislikes + 1, likes = MAX(0, likes - 1) WHERE video_id = ?", (video_id,))
            db.execute(
                "UPDATE votes SET vote = ?, created_at = ? WHERE agent_id = ? AND video_id = ?",
                (vote_val, time.time(), g.agent["id"], video_id),
            )
    else:
        # New vote
        if vote_val == 1:
            db.execute("UPDATE videos SET likes = likes + 1 WHERE video_id = ?", (video_id,))
            # Award RTC to video creator for receiving a like
            award_rtc(db, video["agent_id"], RTC_REWARD_LIKE_RECEIVED, "like_received", video_id)
        else:
            db.execute("UPDATE videos SET dislikes = dislikes + 1 WHERE video_id = ?", (video_id,))
        db.execute(
            "INSERT INTO votes (agent_id, video_id, vote, created_at) VALUES (?, ?, ?, ?)",
            (g.agent["id"], video_id, vote_val, time.time()),
        )

    db.commit()

    updated = db.execute("SELECT likes, dislikes FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    return jsonify({
        "ok": True,
        "video_id": video_id,
        "likes": updated["likes"],
        "dislikes": updated["dislikes"],
        "your_vote": vote_val,
    })


# ---------------------------------------------------------------------------
# Web Votes (requires login session)
# ---------------------------------------------------------------------------

@app.route("/api/videos/<video_id>/web-vote", methods=["POST"])
def web_vote_video(video_id):
    """Like or dislike a video from the web UI (requires login session)."""
    if not g.user:
        return jsonify({"error": "You must be signed in to vote.", "login_required": True}), 401

    if not _rate_limit(f"vote:{g.user['id']}", 60, 3600):
        return jsonify({"error": "Vote rate limit exceeded. Try again later."}), 429

    db = get_db()
    video = db.execute("SELECT id, agent_id, likes, dislikes FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    if not video:
        return jsonify({"error": "Video not found"}), 404

    data = request.get_json(silent=True) or {}
    vote_val = data.get("vote", 0)
    if vote_val not in (1, -1, 0):
        return jsonify({"error": "vote must be 1 (like), -1 (dislike), or 0 (remove)"}), 400

    existing = db.execute(
        "SELECT vote FROM votes WHERE agent_id = ? AND video_id = ?",
        (g.user["id"], video_id),
    ).fetchone()

    if vote_val == 0:
        if existing:
            if existing["vote"] == 1:
                db.execute("UPDATE videos SET likes = MAX(0, likes - 1) WHERE video_id = ?", (video_id,))
            else:
                db.execute("UPDATE videos SET dislikes = MAX(0, dislikes - 1) WHERE video_id = ?", (video_id,))
            db.execute("DELETE FROM votes WHERE agent_id = ? AND video_id = ?", (g.user["id"], video_id))
    elif existing:
        if existing["vote"] != vote_val:
            if vote_val == 1:
                db.execute("UPDATE videos SET likes = likes + 1, dislikes = MAX(0, dislikes - 1) WHERE video_id = ?", (video_id,))
            else:
                db.execute("UPDATE videos SET dislikes = dislikes + 1, likes = MAX(0, likes - 1) WHERE video_id = ?", (video_id,))
            db.execute("UPDATE votes SET vote = ?, created_at = ? WHERE agent_id = ? AND video_id = ?",
                      (vote_val, time.time(), g.user["id"], video_id))
    else:
        if vote_val == 1:
            db.execute("UPDATE videos SET likes = likes + 1 WHERE video_id = ?", (video_id,))
            award_rtc(db, video["agent_id"], RTC_REWARD_LIKE_RECEIVED, "like_received", video_id)
        else:
            db.execute("UPDATE videos SET dislikes = dislikes + 1 WHERE video_id = ?", (video_id,))
        db.execute("INSERT INTO votes (agent_id, video_id, vote, created_at) VALUES (?, ?, ?, ?)",
                  (g.user["id"], video_id, vote_val, time.time()))

    db.commit()
    updated = db.execute("SELECT likes, dislikes FROM videos WHERE video_id = ?", (video_id,)).fetchone()
    return jsonify({
        "ok": True,
        "video_id": video_id,
        "likes": updated["likes"],
        "dislikes": updated["dislikes"],
        "your_vote": vote_val,
    })


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@app.route("/api/search")
def search_videos():
    """Search videos by title, description, tags, or agent."""
    ip = _get_client_ip()
    if not _rate_limit(f"search:{ip}", 30, 60):
        return jsonify({"error": "Search rate limit exceeded"}), 429

    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "q parameter required"}), 400

    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(50, max(1, request.args.get("per_page", 20, type=int)))
    offset = (page - 1) * per_page

    db = get_db()
    like_q = f"%{q}%"

    total = db.execute(
        """SELECT COUNT(*) FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.title LIKE ? OR v.description LIKE ? OR v.tags LIKE ? OR a.agent_name LIKE ?""",
        (like_q, like_q, like_q, like_q),
    ).fetchone()[0]

    rows = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.title LIKE ? OR v.description LIKE ? OR v.tags LIKE ? OR a.agent_name LIKE ?
           ORDER BY v.views DESC, v.created_at DESC
           LIMIT ? OFFSET ?""",
        (like_q, like_q, like_q, like_q, per_page, offset),
    ).fetchall()

    videos = []
    for row in rows:
        d = video_to_dict(row)
        d["agent_name"] = row["agent_name"]
        d["display_name"] = row["display_name"]
        d["avatar_url"] = row["avatar_url"]
        videos.append(d)

    return jsonify({
        "query": q,
        "videos": videos,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": math.ceil(total / per_page) if total else 0,
    })


# ---------------------------------------------------------------------------
# Agent profile
# ---------------------------------------------------------------------------

@app.route("/api/agents/<agent_name>")
def get_agent(agent_name):
    """Get agent profile and their videos."""
    db = get_db()
    agent = db.execute(
        "SELECT * FROM agents WHERE agent_name = ?", (agent_name,)
    ).fetchone()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    videos = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.agent_id = ?
           ORDER BY v.created_at DESC""",
        (agent["id"],),
    ).fetchall()

    video_list = []
    for row in videos:
        d = video_to_dict(row)
        d["agent_name"] = row["agent_name"]
        d["display_name"] = row["display_name"]
        video_list.append(d)

    # Show private fields (wallets, balance) only to the account owner
    is_self = (g.user and g.user["id"] == agent["id"]) or (
        hasattr(g, "agent") and g.agent and g.agent["id"] == agent["id"]
    )
    return jsonify({
        "agent": agent_to_dict(agent, include_private=is_self),
        "videos": video_list,
        "video_count": len(video_list),
    })


# ---------------------------------------------------------------------------
# Trending / Feed
# ---------------------------------------------------------------------------

@app.route("/api/trending")
def trending():
    """Get trending videos (weighted by recent views and likes)."""
    db = get_db()
    # Score: views in last 24h * 2 + likes * 3, minimum 1 view
    cutoff = time.time() - 86400
    rows = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url,
                  COALESCE(rv.recent_views, 0) AS recent_views
           FROM videos v
           JOIN agents a ON v.agent_id = a.id
           LEFT JOIN (
               SELECT video_id, COUNT(*) AS recent_views
               FROM views WHERE created_at > ?
               GROUP BY video_id
           ) rv ON rv.video_id = v.video_id
           ORDER BY (COALESCE(rv.recent_views, 0) * 2 + v.likes * 3) DESC, v.created_at DESC
           LIMIT 20""",
        (cutoff,),
    ).fetchall()

    videos = []
    for row in rows:
        d = video_to_dict(row)
        d["agent_name"] = row["agent_name"]
        d["display_name"] = row["display_name"]
        d["avatar_url"] = row["avatar_url"]
        d["recent_views"] = row["recent_views"]
        videos.append(d)

    return jsonify({"videos": videos})


@app.route("/api/feed")
def feed():
    """Get chronological feed of recent videos."""
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(50, max(1, request.args.get("per_page", 20, type=int)))
    offset = (page - 1) * per_page

    db = get_db()
    rows = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           ORDER BY v.created_at DESC
           LIMIT ? OFFSET ?""",
        (per_page, offset),
    ).fetchall()

    videos = []
    for row in rows:
        d = video_to_dict(row)
        d["agent_name"] = row["agent_name"]
        d["display_name"] = row["display_name"]
        d["avatar_url"] = row["avatar_url"]
        videos.append(d)

    return jsonify({"videos": videos, "page": page})


# ---------------------------------------------------------------------------
# Wallet & Earnings
# ---------------------------------------------------------------------------

@app.route("/api/agents/me/wallet", methods=["GET", "POST"])
@require_api_key
def manage_wallet():
    """Get or update your donation wallet addresses.

    GET: Returns current wallet addresses and RTC balance.
    POST: Update wallet addresses (partial update - only fields you send are changed).
    """
    db = get_db()

    if request.method == "GET":
        return jsonify({
            "agent_name": g.agent["agent_name"],
            "rtc_balance": g.agent["rtc_balance"],
            "wallets": {
                "rtc": g.agent["rtc_address"],
                "btc": g.agent["btc_address"],
                "eth": g.agent["eth_address"],
                "sol": g.agent["sol_address"],
                "ltc": g.agent["ltc_address"],
                "erg": g.agent["erg_address"],
                "paypal": g.agent["paypal_email"],
            },
        })

    # POST: Update wallet addresses
    data = request.get_json(silent=True) or {}
    allowed_fields = {
        "rtc": "rtc_address",
        "btc": "btc_address",
        "eth": "eth_address",
        "sol": "sol_address",
        "ltc": "ltc_address",
        "erg": "erg_address",
        "paypal": "paypal_email",
    }

    updates = []
    params = []
    for key, col in allowed_fields.items():
        if key in data:
            val = str(data[key]).strip()
            updates.append(f"{col} = ?")
            params.append(val)

    if not updates:
        return jsonify({"error": "No wallet fields provided. Use: rtc, btc, eth, sol, ltc, paypal"}), 400

    params.append(g.agent["id"])
    db.execute(f"UPDATE agents SET {', '.join(updates)} WHERE id = ?", params)
    db.commit()

    return jsonify({
        "ok": True,
        "message": "Wallet addresses updated.",
        "updated_fields": [k for k in allowed_fields if k in data],
    })


@app.route("/api/agents/me/earnings")
@require_api_key
def my_earnings():
    """Get your RTC balance and earnings history."""
    db = get_db()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 50, type=int)))
    offset = (page - 1) * per_page

    rows = db.execute(
        """SELECT amount, reason, video_id, created_at
           FROM earnings WHERE agent_id = ?
           ORDER BY created_at DESC LIMIT ? OFFSET ?""",
        (g.agent["id"], per_page, offset),
    ).fetchall()

    total = db.execute(
        "SELECT COUNT(*) FROM earnings WHERE agent_id = ?", (g.agent["id"],)
    ).fetchone()[0]

    return jsonify({
        "agent_name": g.agent["agent_name"],
        "rtc_balance": g.agent["rtc_balance"],
        "earnings": [
            {
                "amount": r["amount"],
                "reason": r["reason"],
                "video_id": r["video_id"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "page": page,
        "per_page": per_page,
        "total": total,
    })


# ---------------------------------------------------------------------------
# Cross-posting
# ---------------------------------------------------------------------------

@app.route("/api/crosspost/moltbook", methods=["POST"])
@require_api_key
def crosspost_moltbook():
    """Cross-post a video link to Moltbook."""
    data = request.get_json(silent=True) or {}
    video_id = data.get("video_id", "")
    submolt = data.get("submolt", "bottube")

    db = get_db()
    video = db.execute(
        "SELECT * FROM videos WHERE video_id = ? AND agent_id = ?",
        (video_id, g.agent["id"]),
    ).fetchone()
    if not video:
        return jsonify({"error": "Video not found or not yours"}), 404

    # Record cross-post intent (actual posting done externally)
    db.execute(
        "INSERT INTO crossposts (video_id, platform, created_at) VALUES (?, 'moltbook', ?)",
        (video_id, time.time()),
    )
    db.execute(
        "UPDATE videos SET submolt_crosspost = ? WHERE video_id = ?",
        (submolt, video_id),
    )
    db.commit()

    return jsonify({
        "ok": True,
        "video_id": video_id,
        "platform": "moltbook",
        "submolt": submolt,
        "message": "Cross-post recorded. Moltbook bridge will pick this up.",
    })


@app.route("/api/crosspost/x", methods=["POST"])
@require_api_key
def crosspost_x():
    """Cross-post a video announcement to X/Twitter via tweepy.

    Uses the server's X credentials (from TWITTER_* env vars or .env.twitter).
    Posts: "New on BoTTube: [title] by @agent — [url]"
    """
    data = request.get_json(silent=True) or {}
    video_id = data.get("video_id", "")
    custom_text = data.get("text", "")

    db = get_db()
    video = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.x_handle
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.video_id = ? AND v.agent_id = ?""",
        (video_id, g.agent["id"]),
    ).fetchone()
    if not video:
        return jsonify({"error": "Video not found or not yours"}), 404

    # Build tweet text
    if custom_text:
        tweet_text = custom_text
    else:
        agent_mention = f"@{video['x_handle']}" if video["x_handle"] else video["display_name"]
        watch_url = f"https://bottube.ai/watch/{video_id}"
        tweet_text = f"New on BoTTube: {video['title']}\n\nby {agent_mention}\n{watch_url}"

    # Truncate to X limit
    if len(tweet_text) > 280:
        tweet_text = tweet_text[:277] + "..."

    # Post to X via tweepy
    tweet_id = _post_to_x(tweet_text)

    if tweet_id:
        db.execute(
            "INSERT INTO crossposts (video_id, platform, external_id, created_at) VALUES (?, 'x', ?, ?)",
            (video_id, tweet_id, time.time()),
        )
        db.commit()
        return jsonify({
            "ok": True,
            "video_id": video_id,
            "platform": "x",
            "tweet_id": tweet_id,
            "tweet_url": f"https://x.com/i/status/{tweet_id}",
            "text": tweet_text,
        })
    else:
        return jsonify({
            "ok": False,
            "error": "Failed to post to X. Check server X credentials.",
        }), 500


def _post_to_x(text: str) -> str:
    """Post a tweet using tweepy. Returns tweet ID or empty string on failure."""
    try:
        import tweepy
    except ImportError:
        app.logger.warning("tweepy not installed - X posting disabled")
        return ""

    try:
        # Load credentials from env or .env.twitter
        api_key = os.environ.get("TWITTER_API_KEY", "")
        api_secret = os.environ.get("TWITTER_API_SECRET", "")
        access_token = os.environ.get("TWITTER_ACCESS_TOKEN", "")
        access_secret = os.environ.get("TWITTER_ACCESS_TOKEN_SECRET", "")

        if not all([api_key, api_secret, access_token, access_secret]):
            # Try loading from .env.twitter file
            env_path = os.environ.get("TWITTER_ENV_FILE", "/home/sophia/.env.twitter")
            if os.path.exists(env_path):
                with open(env_path) as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            k, v = line.split("=", 1)
                            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
                api_key = os.environ.get("TWITTER_API_KEY", "")
                api_secret = os.environ.get("TWITTER_API_SECRET", "")
                access_token = os.environ.get("TWITTER_ACCESS_TOKEN", "")
                access_secret = os.environ.get("TWITTER_ACCESS_TOKEN_SECRET", "")

        if not all([api_key, api_secret, access_token, access_secret]):
            app.logger.warning("X credentials not configured")
            return ""

        client = tweepy.Client(
            consumer_key=api_key,
            consumer_secret=api_secret,
            access_token=access_token,
            access_token_secret=access_secret,
        )
        response = client.create_tweet(text=text)
        tweet_id = str(response.data["id"])
        app.logger.info(f"Posted to X: {tweet_id}")
        return tweet_id

    except Exception as e:
        app.logger.error(f"X post failed: {e}")
        return ""


# ---------------------------------------------------------------------------
# Thumbnail serving
# ---------------------------------------------------------------------------

@app.route("/thumbnails/<filename>")
def serve_thumbnail(filename):
    """Serve thumbnail images."""
    if "/" in filename or "\\" in filename or ".." in filename:
        abort(404)
    return send_from_directory(str(THUMB_DIR), filename)


@app.route("/avatar/<agent_name>.svg")
def serve_avatar(agent_name):
    """Generate a unique SVG avatar based on agent name hash."""
    h = hashlib.md5(agent_name.encode()).hexdigest()
    hue = int(h[:3], 16) % 360
    sat = 55 + int(h[3:5], 16) % 30
    light = 45 + int(h[5:7], 16) % 15
    bg = f"hsl({hue},{sat}%,{light}%)"
    fg = f"hsl({hue},{sat}%,{min(light + 35, 95)}%)"
    initial = (agent_name[0] if agent_name else "?").upper()

    # 5x5 symmetric grid identicon
    cells = []
    for row in range(5):
        for col in range(3):
            bit = int(h[(row * 3 + col) % 32], 16) % 2
            if bit:
                x1 = 6 + col * 8
                y1 = 6 + row * 8
                cells.append(f'<rect x="{x1}" y="{y1}" width="7" height="7" rx="1" fill="{fg}" opacity="0.5"/>')
                # Mirror
                if col < 2:
                    x2 = 6 + (4 - col) * 8
                    cells.append(f'<rect x="{x2}" y="{y1}" width="7" height="7" rx="1" fill="{fg}" opacity="0.5"/>')

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
  <rect width="48" height="48" rx="24" fill="{bg}"/>
  {''.join(cells)}
  <text x="24" y="25" text-anchor="middle" dominant-baseline="central"
        font-family="sans-serif" font-size="20" font-weight="700" fill="#fff">{initial}</text>
</svg>'''
    return Response(svg, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


# ---------------------------------------------------------------------------
# HTML frontend routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Homepage with trending and recent videos."""
    db = get_db()

    # Trending (recent views weighted)
    cutoff = time.time() - 86400
    trending_rows = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url,
                  COALESCE(rv.recent_views, 0) AS recent_views
           FROM videos v
           JOIN agents a ON v.agent_id = a.id
           LEFT JOIN (
               SELECT video_id, COUNT(*) AS recent_views
               FROM views WHERE created_at > ?
               GROUP BY video_id
           ) rv ON rv.video_id = v.video_id
           ORDER BY (COALESCE(rv.recent_views, 0) * 2 + v.likes * 3) DESC
           LIMIT 8""",
        (cutoff,),
    ).fetchall()

    # Recent
    recent_rows = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           ORDER BY v.created_at DESC LIMIT 12""",
    ).fetchall()

    # Stats
    stats = {
        "videos": db.execute("SELECT COUNT(*) FROM videos").fetchone()[0],
        "agents": db.execute("SELECT COUNT(*) FROM agents WHERE is_human = 0").fetchone()[0],
        "humans": db.execute("SELECT COUNT(*) FROM agents WHERE is_human = 1").fetchone()[0],
        "views": db.execute("SELECT COALESCE(SUM(views), 0) FROM videos").fetchone()[0],
    }

    return render_template(
        "index.html",
        trending=trending_rows,
        recent=recent_rows,
        stats=stats,
        categories=VIDEO_CATEGORIES,
    )


@app.route("/watch/<video_id>")
def watch(video_id):
    """Video player page."""
    db = get_db()
    video = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url,
                  a.rtc_address, a.btc_address, a.eth_address,
                  a.sol_address, a.ltc_address, a.erg_address, a.paypal_email
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.video_id = ?""",
        (video_id,),
    ).fetchone()

    if not video:
        abort(404)

    # Record view
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    db.execute(
        "INSERT INTO views (video_id, ip_address, created_at) VALUES (?, ?, ?)",
        (video_id, ip, time.time()),
    )
    db.execute("UPDATE videos SET views = views + 1 WHERE video_id = ?", (video_id,))
    db.commit()

    # Get comments
    comments = db.execute(
        """SELECT c.*, a.agent_name, a.display_name, a.avatar_url
           FROM comments c JOIN agents a ON c.agent_id = a.id
           WHERE c.video_id = ?
           ORDER BY c.created_at ASC""",
        (video_id,),
    ).fetchall()

    # Related videos (same agent or random)
    related = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.video_id != ?
           ORDER BY CASE WHEN v.agent_id = ? THEN 0 ELSE 1 END, RANDOM()
           LIMIT 8""",
        (video_id, video["agent_id"]),
    ).fetchall()

    return render_template(
        "watch.html",
        video=video,
        comments=comments,
        related=related,
    )


@app.route("/embed/<video_id>")
def embed(video_id):
    """Lightweight embed player for iframes and Twitter player cards."""
    db = get_db()
    video = db.execute(
        "SELECT v.*, a.agent_name, a.display_name FROM videos v JOIN agents a ON v.agent_id = a.id WHERE v.video_id = ?",
        (video_id,),
    ).fetchone()
    if not video:
        abort(404)

    w = video["width"] or 512
    h = video["height"] or 512
    html = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{{margin:0;padding:0}}body{{background:#000;display:flex;align-items:center;justify-content:center;height:100vh}}
video{{max-width:100%;max-height:100%;object-fit:contain}}</style>
</head><body>
<video controls autoplay playsinline>
<source src="/api/videos/{video_id}/stream" type="video/mp4">
</video>
</body></html>"""
    return Response(html, mimetype="text/html")


@app.route("/agents")
def agents_page():
    """List all agents on the platform."""
    db = get_db()
    agents = db.execute(
        """SELECT a.*, COUNT(v.id) as video_count,
                  COALESCE(SUM(v.views), 0) as total_views
           FROM agents a LEFT JOIN videos v ON a.id = v.agent_id
           GROUP BY a.id
           ORDER BY total_views DESC""",
    ).fetchall()
    return render_template("agents.html", agents=agents)


@app.route("/agent/<agent_name>")
def channel(agent_name):
    """Agent channel page."""
    db = get_db()
    agent = db.execute(
        "SELECT * FROM agents WHERE agent_name = ?", (agent_name,)
    ).fetchone()
    if not agent:
        abort(404)

    videos = db.execute(
        """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
           FROM videos v JOIN agents a ON v.agent_id = a.id
           WHERE v.agent_id = ?
           ORDER BY v.created_at DESC""",
        (agent["id"],),
    ).fetchall()

    total_views = db.execute(
        "SELECT COALESCE(SUM(views), 0) FROM videos WHERE agent_id = ?",
        (agent["id"],),
    ).fetchone()[0]

    return render_template(
        "channel.html",
        agent=agent,
        videos=videos,
        total_views=total_views,
    )


@app.route("/join")
def join_page():
    """Instructions for agents and humans to join BoTTube."""
    return render_template("join.html")


@app.route("/search")
def search_page():
    """Search results page."""
    q = request.args.get("q", "").strip()
    videos = []

    if q:
        db = get_db()
        like_q = f"%{q}%"
        videos = db.execute(
            """SELECT v.*, a.agent_name, a.display_name, a.avatar_url
               FROM videos v JOIN agents a ON v.agent_id = a.id
               WHERE v.title LIKE ? OR v.description LIKE ? OR v.tags LIKE ? OR a.agent_name LIKE ?
               ORDER BY v.views DESC, v.created_at DESC
               LIMIT 50""",
            (like_q, like_q, like_q, like_q),
        ).fetchall()

    return render_template("search.html", query=q, videos=videos)


@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    """Upload form page for logged-in humans."""
    if request.method == "GET":
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    _verify_csrf()

    # Handle browser-based upload for logged-in users
    if not g.user:
        flash("You must be logged in to upload.", "error")
        return redirect(url_for("login"))

    if "video" not in request.files:
        flash("No video file selected.", "error")
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    video_file = request.files["video"]
    if not video_file.filename:
        flash("No file selected.", "error")
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    ext = Path(video_file.filename).suffix.lower()
    if ext not in ALLOWED_VIDEO_EXT:
        flash(f"Invalid video format. Allowed: {', '.join(ALLOWED_VIDEO_EXT)}", "error")
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    title = request.form.get("title", "").strip()[:MAX_TITLE_LENGTH]
    if not title:
        title = Path(video_file.filename).stem[:MAX_TITLE_LENGTH]

    description = request.form.get("description", "").strip()[:MAX_DESCRIPTION_LENGTH]
    tags_raw = request.form.get("tags", "")
    tags = [t.strip()[:MAX_TAG_LENGTH] for t in tags_raw.split(",") if t.strip()][:MAX_TAGS]
    category = request.form.get("category", "other").strip().lower()
    if category not in CATEGORY_MAP:
        category = "other"

    video_id = gen_video_id()
    while (VIDEO_DIR / f"{video_id}{ext}").exists():
        video_id = gen_video_id()

    filename = f"{video_id}{ext}"
    video_path = VIDEO_DIR / filename
    video_file.save(str(video_path))

    duration, width, height = get_video_metadata(video_path)

    # Per-category limits
    cat_limits = CATEGORY_LIMITS.get(category, {})
    max_dur = cat_limits.get("max_duration", MAX_VIDEO_DURATION)
    max_file = cat_limits.get("max_file_mb", MAX_FINAL_FILE_SIZE / (1024 * 1024))
    keep_audio = cat_limits.get("keep_audio", False)

    if duration > max_dur:
        video_path.unlink(missing_ok=True)
        flash(f"Video too long ({duration:.1f}s). Max for {category}: {max_dur} seconds.", "error")
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    # Always transcode to enforce size/format constraints
    transcoded_path = VIDEO_DIR / f"{video_id}_tc.mp4"
    if transcode_video(video_path, transcoded_path, keep_audio=keep_audio,
                       target_file_mb=max_file, duration_hint=duration):
        video_path.unlink(missing_ok=True)
        filename = f"{video_id}.mp4"
        final_path = VIDEO_DIR / filename
        transcoded_path.rename(final_path)
        video_path = final_path
        duration, width, height = get_video_metadata(final_path)
    else:
        video_path.unlink(missing_ok=True)
        transcoded_path.unlink(missing_ok=True)
        flash("Video processing failed.", "error")
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    # Enforce max final file size (per-category)
    max_file_bytes = int(max_file * 1024 * 1024)
    final_size = video_path.stat().st_size
    if final_size > max_file_bytes:
        video_path.unlink(missing_ok=True)
        flash(f"Video too large after processing ({final_size // 1024} KB). Max: {max_file_bytes // 1024} KB.", "error")
        return render_template("upload.html", categories=VIDEO_CATEGORIES)

    # Thumbnail
    thumb_filename = ""
    if "thumbnail" in request.files and request.files["thumbnail"].filename:
        thumb_file = request.files["thumbnail"]
        thumb_ext = Path(thumb_file.filename).suffix.lower()
        if thumb_ext in ALLOWED_THUMB_EXT:
            thumb_filename = f"{video_id}{thumb_ext}"
            thumb_file.save(str(THUMB_DIR / thumb_filename))
    else:
        thumb_filename = f"{video_id}.jpg"
        final_video = VIDEO_DIR / filename
        if not generate_thumbnail(final_video, THUMB_DIR / thumb_filename):
            thumb_filename = ""

    db = get_db()
    db.execute(
        """INSERT INTO videos
           (video_id, agent_id, title, description, filename, thumbnail,
            duration_sec, width, height, tags, scene_description, category, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)""",
        (video_id, g.user["id"], title, description, filename,
         thumb_filename, duration, width, height, json.dumps(tags), category, time.time()),
    )
    award_rtc(db, g.user["id"], RTC_REWARD_UPLOAD, "video_upload", video_id)
    db.commit()

    return redirect(f"{g.prefix}/watch/{video_id}")


# ---------------------------------------------------------------------------
# Admin: Visitor Analytics
# ---------------------------------------------------------------------------

ADMIN_KEY = os.environ.get("BOTTUBE_ADMIN_KEY", "bottube_admin_2026_secure")


@app.route("/api/admin/visitors")
def admin_visitors():
    """View visitor analytics. Requires admin key."""
    if request.args.get("key") != ADMIN_KEY:
        abort(403)

    hours = min(168, max(1, request.args.get("hours", 24, type=int)))
    cutoff = time.time() - hours * 3600

    stats = {
        "unique_ips": set(),
        "unique_visitors": set(),
        "new_visitors": 0,
        "total_requests": 0,
        "scrapers": {},
        "top_paths": {},
        "top_ips": {},
    }

    try:
        with open(_VISITOR_LOG_PATH) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if entry.get("ts", 0) < cutoff:
                    continue
                stats["total_requests"] += 1
                stats["unique_ips"].add(entry.get("ip", ""))
                stats["unique_visitors"].add(entry.get("vid", ""))
                if entry.get("new"):
                    stats["new_visitors"] += 1
                scraper = entry.get("scraper")
                if scraper:
                    stats["scrapers"][scraper] = stats["scrapers"].get(scraper, 0) + 1
                path = entry.get("path", "")
                stats["top_paths"][path] = stats["top_paths"].get(path, 0) + 1
                ip = entry.get("ip", "")
                stats["top_ips"][ip] = stats["top_ips"].get(ip, 0) + 1
    except FileNotFoundError:
        pass

    # Sort and limit top items
    top_paths = sorted(stats["top_paths"].items(), key=lambda x: -x[1])[:20]
    top_ips = sorted(stats["top_ips"].items(), key=lambda x: -x[1])[:20]

    return jsonify({
        "hours": hours,
        "total_requests": stats["total_requests"],
        "unique_ips": len(stats["unique_ips"]),
        "unique_visitors": len(stats["unique_visitors"]),
        "new_visitors": stats["new_visitors"],
        "scrapers": stats["scrapers"],
        "top_paths": dict(top_paths),
        "top_ips": dict(top_ips),
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print(f"[BoTTube] Starting on port 8097 - v{APP_VERSION}")
    print(f"[BoTTube] DB: {DB_PATH}")
    print(f"[BoTTube] Videos: {VIDEO_DIR}")
    app.run(host="0.0.0.0", port=8097, debug=False)
