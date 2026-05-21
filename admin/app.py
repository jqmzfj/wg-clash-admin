#!/usr/bin/env python3
import base64
import hashlib
import hmac
import os
import re
import secrets
import shlex
import shutil
import subprocess
import threading
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
import redis
import yaml
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
    send_file,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix


ADMIN_DIR = Path(__file__).resolve().parent
VPN_DIR = Path(os.environ.get("VPN_DIR", ADMIN_DIR.parent)).resolve()
ENV_FILE = VPN_DIR / ".env"
COMPOSE_FILE = VPN_DIR / "docker-compose.yml"
CLASH_FILE = VPN_DIR / "clash-config.yaml"
RUN_SCRIPT = VPN_DIR / "run.sh"
PEER_ROOT = VPN_DIR / "vpn-config"
UPDATE_REPO_DIR = Path(os.environ.get("UPDATE_REPO_DIR", VPN_DIR / "wg-clash-admin")).resolve()
UPDATE_REPO_URL = os.environ.get("UPDATE_REPO_URL", "https://github.com/jqmzfj/wg-clash-admin.git").strip()
UPDATE_BRANCH = os.environ.get("UPDATE_BRANCH", "").strip()
UPDATE_VERSION_FILE = os.environ.get("UPDATE_VERSION_FILE", "VERSION").strip() or "VERSION"
UPDATE_CHECK_INTERVAL_SECONDS = int(os.environ.get("UPDATE_CHECK_INTERVAL_SECONDS", "18000"))
UPDATE_SYNC_COMPOSE = os.environ.get("UPDATE_SYNC_COMPOSE", "false").lower() == "true"
UPDATE_SYNC_PATHS = os.environ.get(
    "UPDATE_SYNC_PATHS",
    "admin,run.sh,generate_clash_yaml.py,README.md,.env.example,VERSION",
)
UPDATE_STATE_KEY = "version:update_state"
SESSION_TTL_SECONDS = 60 * 60 * 24 * 14
LOCK_TTL_SECONDS = 180
RESERVED_PORTS = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2375, 2376, 5432, 6379}
APP_STARTED_AT = int(time.time())
EXTERNAL_SUBSCRIPTION_TIMEOUT = float(os.environ.get("EXTERNAL_SUBSCRIPTION_TIMEOUT", "4"))
EXTERNAL_SUBSCRIPTION_MAX_BYTES = int(os.environ.get("EXTERNAL_SUBSCRIPTION_MAX_BYTES", "1048576"))
EXTERNAL_SUBSCRIPTION_CACHE_TTL = int(os.environ.get("EXTERNAL_SUBSCRIPTION_CACHE_TTL", "300"))
EXTERNAL_SUBSCRIPTION_STALE_TTL = int(os.environ.get("EXTERNAL_SUBSCRIPTION_STALE_TTL", "86400"))
EXTERNAL_SUBSCRIPTION_FAILURE_LOG_COOLDOWN = int(
    os.environ.get("EXTERNAL_SUBSCRIPTION_FAILURE_LOG_COOLDOWN", "1800")
)
EXTERNAL_SUBSCRIPTION_PROXY = os.environ.get("EXTERNAL_SUBSCRIPTION_PROXY", "").strip()
EXTERNAL_SUBSCRIPTION_MAX_FAILURES = int(os.environ.get("EXTERNAL_SUBSCRIPTION_MAX_FAILURES", "10"))
APP_TIMEZONE = ZoneInfo(os.environ.get("TZ", "Asia/Shanghai"))


app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    SEND_FILE_MAX_AGE_DEFAULT=0,
    TEMPLATES_AUTO_RELOAD=True,
)
app.jinja_env.auto_reload = True


class PrefixMiddleware:
    def __init__(self, wrapped_app, prefix):
        self.wrapped_app = wrapped_app
        self.prefix = prefix.rstrip("/")

    def __call__(self, environ, start_response):
        if not self.prefix:
            return self.wrapped_app(environ, start_response)
        path = environ.get("PATH_INFO", "")
        script_name = environ.get("SCRIPT_NAME", "")
        next_script_name = script_name if script_name.endswith(self.prefix) else script_name + self.prefix
        if path == self.prefix:
            environ["SCRIPT_NAME"] = next_script_name
            environ["PATH_INFO"] = "/"
        elif path.startswith(self.prefix + "/"):
            environ["SCRIPT_NAME"] = next_script_name
            environ["PATH_INFO"] = path[len(self.prefix):]
        else:
            environ["SCRIPT_NAME"] = next_script_name
        return self.wrapped_app(environ, start_response)


URL_PREFIX = os.environ.get("URL_PREFIX", "").rstrip("/")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
if URL_PREFIX:
    app.wsgi_app = PrefixMiddleware(app.wsgi_app, URL_PREFIX)


@app.route("/favicon.ico")
def favicon():
    return send_file(ADMIN_DIR / "static" / "favicon.svg", mimetype="image/svg+xml")


@app.after_request
def add_cache_headers(response):
    if request.endpoint in {"dashboard", "login", "static"}:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def env(name, default):
    return os.environ.get(name, default)


def required_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def now_local():
    return datetime.now(APP_TIMEZONE)


def to_local_datetime(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).astimezone(APP_TIMEZONE)
    return value.astimezone(APP_TIMEZONE)


def format_local_datetime(value, fmt="%Y-%m-%d %H:%M:%S"):
    local_value = to_local_datetime(value)
    return local_value.strftime(fmt) if local_value else ""


def get_db():
    if "db" not in g:
        g.db = psycopg.connect(required_env("DATABASE_URL"))
    return g.db


def get_redis():
    if "redis" not in g:
        g.redis = redis.from_url(required_env("REDIS_URL"), decode_responses=True)
    return g.redis


@app.teardown_appcontext
def close_resources(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
    redis_client = g.pop("redis", None)
    if redis_client is not None:
        redis_client.close()


def init_db():
    with app.app_context():
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    sub_token TEXT UNIQUE,
                    sub_token_hash TEXT UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_token TEXT UNIQUE")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS operation_logs (
                    id BIGSERIAL PRIMARY KEY,
                    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    success BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS external_subscriptions (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    suspended BOOLEAN NOT NULL DEFAULT FALSE,
                    last_error TEXT NOT NULL DEFAULT '',
                    last_failed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                "ALTER TABLE external_subscriptions ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0"
            )
            cur.execute(
                "ALTER TABLE external_subscriptions ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT FALSE"
            )
            cur.execute("ALTER TABLE external_subscriptions ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE external_subscriptions ADD COLUMN IF NOT EXISTS last_failed_at TIMESTAMPTZ")
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
            if user_count == 0:
                username = env("ADMIN_USERNAME", "admin")
                password = required_env("ADMIN_PASSWORD")
                token = generate_token()
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role, sub_token, sub_token_hash)
                    VALUES (%s, %s, 'admin', %s, %s)
                    """,
                    (username, hash_password(password), token, hash_token(token)),
                )
                print(f"Created admin user: {username}")
                print(f"Initial subscription token, save it now: {token}")
            cur.execute("SELECT id, username FROM users WHERE sub_token IS NULL")
            for user_id, username in cur.fetchall():
                token = generate_token()
                cur.execute(
                    """
                    UPDATE users
                    SET sub_token = %s, sub_token_hash = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (token, hash_token(token), user_id),
                )
                print(f"Generated visible subscription token for existing user: {username}")
            for key, value in read_runtime_config().items():
                cur.execute(
                    """
                    INSERT INTO settings (key, value)
                    VALUES (%s, %s)
                    ON CONFLICT (key) DO NOTHING
                    """,
                    (key, str(value)),
                )
        db.commit()


@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Database initialized.")


@app.cli.command("wait-services")
def wait_services_command():
    wait_seconds = int(env("STARTUP_WAIT_SECONDS", "90"))
    deadline = time.monotonic() + wait_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(required_env("DATABASE_URL"), connect_timeout=3) as db:
                with db.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            r = redis.from_url(required_env("REDIS_URL"), decode_responses=True)
            if r.ping():
                print("PostgreSQL and Redis are ready.")
                return
        except Exception as exc:
            last_error = str(exc)
            print(f"Waiting for PostgreSQL/Redis: {last_error}", flush=True)
            time.sleep(3)
    raise RuntimeError(f"PostgreSQL/Redis not ready after {wait_seconds}s: {last_error}")


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return "pbkdf2_sha256$240000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password, stored):
    try:
        algo, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def generate_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def query_one(sql, params=()):
    with get_db().cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        names = [desc.name for desc in cur.description]
        return dict(zip(names, row))


def query_all(sql, params=()):
    with get_db().cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
        names = [desc.name for desc in cur.description]
        return [dict(zip(names, row)) for row in rows]


def log_action(action, detail="", success=True):
    user = getattr(g, "user", None)
    user_id = user["id"] if user else None
    with get_db().cursor() as cur:
        cur.execute(
            "INSERT INTO operation_logs (actor_user_id, action, detail, success) VALUES (%s, %s, %s, %s)",
            (user_id, action, detail, success),
        )
    get_db().commit()


def log_system_action(action, detail="", success=True):
    with get_db().cursor() as cur:
        cur.execute(
            "INSERT INTO operation_logs (actor_user_id, action, detail, success) VALUES (%s, %s, %s, %s)",
            (None, action, detail[:1800], success),
        )
    get_db().commit()


def log_system_action_once(action, detail="", success=True, cooldown_seconds=300, scope=""):
    redis_client = get_redis()
    cache_input = f"{action}|{success}|{scope}|{detail[:1800]}"
    cache_key = "log-once:" + hashlib.sha256(cache_input.encode("utf-8")).hexdigest()
    if not redis_client.set(cache_key, "1", nx=True, ex=max(1, cooldown_seconds)):
        return
    log_system_action(action, detail, success)


def get_setting(key, default=""):
    row = query_one("SELECT value FROM settings WHERE key = %s", (key,))
    return row["value"] if row else default


def set_setting(key, value):
    with get_db().cursor() as cur:
        cur.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            (key, str(value)),
        )
    get_db().commit()


def read_env_file():
    values = {}
    if not ENV_FILE.exists():
        return values
    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def update_env_file(values):
    existing = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    if ENV_FILE.exists():
        backup_file(ENV_FILE)
    seen = set()
    output = []
    for raw_line in existing:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            output.append(raw_line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in values:
            output.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            output.append(raw_line)
    for key, value in values.items():
        if key not in seen:
            output.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(output) + "\n", encoding="utf-8")


def config_value(key, default):
    file_values = read_env_file()
    if key in file_values and file_values[key]:
        return file_values[key]
    if os.environ.get(key):
        return os.environ[key]
    text = COMPOSE_FILE.read_text(encoding="utf-8") if COMPOSE_FILE.exists() else ""
    match = re.search(rf"{re.escape(key)}=\$\{{{re.escape(key)}(?::-[^}}]*)?\}}", text)
    if match:
        default_match = re.search(rf"\$\{{{re.escape(key)}:-([^}}]+)\}}", match.group(0))
        if default_match:
            return default_match.group(1)
    return default


def read_runtime_config():
    server_url = config_value("SERVERURL", "127.0.0.1")
    server_port = int(config_value("SERVERPORT", "51820"))
    peers = int(config_value("PEERS", "1"))
    local_node_prefix = config_value("LOCAL_NODE_PREFIX", "peer")
    return {"server_url": server_url, "server_port": server_port, "peers": peers, "local_node_prefix": local_node_prefix}


def regex_value(text, pattern, default):
    match = re.search(pattern, text)
    return match.group(1) if match else default


def validate_port(port):
    if port < 1 or port > 65535:
        raise ValueError("端口必须在 1-65535 之间")
    if port in RESERVED_PORTS:
        raise ValueError(f"{port} 是保留端口，不建议用于 WireGuard 外网入口")


def validate_peers(peers):
    if peers < 1 or peers > 250:
        raise ValueError("PEERS 必须在 1-250 之间")


def acquire_operation_lock(name="vpn-admin-lock"):
    lock_id = secrets.token_hex(16)
    if not get_redis().set(name, lock_id, nx=True, ex=LOCK_TTL_SECONDS):
        return None
    return lock_id


def release_operation_lock(lock_id, name="vpn-admin-lock"):
    script = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
    get_redis().eval(script, 1, name, lock_id)


@contextmanager
def operation_lock(name="vpn-admin-lock"):
    lock_id = acquire_operation_lock(name)
    if not lock_id:
        raise RuntimeError("已有刷新或切换任务正在执行，请稍后再试")
    try:
        yield
    finally:
        release_operation_lock(lock_id, name)


def backup_file(path):
    stamp = now_local().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.{stamp}.bak")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def update_compose(server_url, port, peers, local_node_prefix):
    update_env_file({
        "SERVERURL": server_url,
        "SERVERPORT": str(port),
        "PEERS": str(peers),
        "LOCAL_NODE_PREFIX": local_node_prefix,
    })


def update_peer_endpoints(server_url, port):
    for conf in PEER_ROOT.glob("peer*/peer*.conf"):
        text = conf.read_text(encoding="utf-8")
        if "Endpoint =" not in text:
            continue
        backup_file(conf)
        text = re.sub(r"Endpoint\s*=\s*[^:\s]+:\d+", f"Endpoint = {server_url}:{port}", text)
        conf.write_text(text, encoding="utf-8")


def run_command(args, timeout=120, cwd=None):
    completed = subprocess.run(args, cwd=cwd or VPN_DIR, text=True, capture_output=True, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "命令执行失败").strip())
    return completed.stdout.strip()


def repo_git_command(args, timeout=30):
    return run_command(["git", "-c", f"safe.directory={UPDATE_REPO_DIR}", *args], timeout=timeout, cwd=UPDATE_REPO_DIR)


def optional_repo_git_command(args, timeout=10):
    try:
        return repo_git_command(args, timeout=timeout)
    except Exception:
        return ""


def safe_relative_path(value):
    rel = value.strip()
    path = Path(rel)
    if not rel or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"非法同步路径：{value}")
    return path


def parse_update_sync_paths():
    paths = []
    for raw_path in UPDATE_SYNC_PATHS.split(","):
        raw_path = raw_path.strip()
        if raw_path:
            paths.append(safe_relative_path(raw_path))
    compose_path = Path("docker-compose.yml")
    if UPDATE_SYNC_COMPOSE and compose_path not in paths:
        paths.append(compose_path)
    return paths


def read_version(path):
    if not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        version = line.strip()
        if version:
            return version
    return ""


def local_version_file():
    return VPN_DIR / safe_relative_path(UPDATE_VERSION_FILE)


def get_update_branch():
    if UPDATE_BRANCH:
        return UPDATE_BRANCH
    branch = optional_repo_git_command(["rev-parse", "--abbrev-ref", "HEAD"], timeout=8)
    if branch and branch != "HEAD":
        return branch
    origin_head = optional_repo_git_command(["symbolic-ref", "refs/remotes/origin/HEAD"], timeout=8)
    prefix = "refs/remotes/origin/"
    if origin_head.startswith(prefix):
        return origin_head[len(prefix):]
    return "main"


def ensure_update_repo():
    if not UPDATE_REPO_DIR.exists():
        if not UPDATE_REPO_URL:
            raise RuntimeError(f"源码仓库目录不存在：{UPDATE_REPO_DIR}")
        UPDATE_REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
        branch_args = ["--branch", UPDATE_BRANCH] if UPDATE_BRANCH else []
        run_command(["git", "clone", *branch_args, UPDATE_REPO_URL, str(UPDATE_REPO_DIR)], timeout=600, cwd=UPDATE_REPO_DIR.parent)
    if not (UPDATE_REPO_DIR / ".git").exists():
        raise RuntimeError(f"源码仓库目录不是 Git 仓库：{UPDATE_REPO_DIR}")
    if repo_git_command(["rev-parse", "--is-inside-work-tree"], timeout=8) != "true":
        raise RuntimeError(f"源码仓库目录不是有效 Git 工作区：{UPDATE_REPO_DIR}")


def write_update_state(**values):
    normalized = {key: "" if value is None else str(value) for key, value in values.items()}
    get_redis().hset(UPDATE_STATE_KEY, mapping=normalized)


def check_remote_version():
    ensure_update_repo()
    branch = get_update_branch()
    version_path = safe_relative_path(UPDATE_VERSION_FILE).as_posix()
    repo_git_command(["fetch", "--quiet", "origin"], timeout=180)
    remote_version_text = repo_git_command(["show", f"origin/{branch}:{version_path}"], timeout=30)
    remote_version = remote_version_text.splitlines()[0].strip() if remote_version_text.splitlines() else ""
    local_version = read_version(local_version_file())
    return {
        "local_version": local_version or "未安装版本",
        "remote_version": remote_version,
        "branch": branch,
        "repo_dir": str(UPDATE_REPO_DIR),
        "repo_url": UPDATE_REPO_URL,
        "sync_paths": ", ".join(path.as_posix() for path in parse_update_sync_paths()),
        "update_available": "1" if remote_version and remote_version != local_version else "0",
        "checked_at": now_local().strftime("%Y-%m-%d %H:%M:%S"),
        "checked_epoch": str(int(time.time())),
        "checking": "0",
        "error": "",
    }


def check_update_background(lock_id):
    with app.app_context():
        try:
            write_update_state(**check_remote_version())
        except Exception as exc:
            write_update_state(
                local_version=read_version(local_version_file()) or "未安装版本",
                remote_version="",
                branch=UPDATE_BRANCH or "",
                repo_dir=str(UPDATE_REPO_DIR),
                repo_url=UPDATE_REPO_URL,
                sync_paths=", ".join(path.as_posix() for path in parse_update_sync_paths()),
                update_available="0",
                checked_at=now_local().strftime("%Y-%m-%d %H:%M:%S"),
                checked_epoch=str(int(time.time())),
                checking="0",
                error=str(exc),
            )
        finally:
            release_operation_lock(lock_id, "version-check-lock")


def maybe_start_update_check(force=False):
    state = get_redis().hgetall(UPDATE_STATE_KEY)
    checked_epoch = int(state.get("checked_epoch") or "0")
    if not force and checked_epoch and time.time() - checked_epoch < UPDATE_CHECK_INTERVAL_SECONDS:
        return False
    lock_id = acquire_operation_lock("version-check-lock")
    if not lock_id:
        return False
    get_redis().hset(UPDATE_STATE_KEY, mapping={"checking": "1"})
    worker = threading.Thread(target=check_update_background, args=(lock_id,), daemon=True)
    worker.start()
    return True


def get_version_info():
    maybe_start_update_check()
    state = get_redis().hgetall(UPDATE_STATE_KEY)
    actual_local_version = read_version(local_version_file()) or "未安装版本"
    remote_version = state.get("remote_version") or ""
    state_local_version = state.get("local_version") or actual_local_version
    if state_local_version != actual_local_version:
        state_local_version = actual_local_version
        if remote_version:
            state["update_available"] = "1" if remote_version != actual_local_version else "0"
    return {
        "local_version": state_local_version,
        "remote_version": remote_version,
        "branch": state.get("branch") or UPDATE_BRANCH or "main",
        "repo_dir": state.get("repo_dir") or str(UPDATE_REPO_DIR),
        "repo_url": state.get("repo_url") or UPDATE_REPO_URL,
        "sync_paths": state.get("sync_paths") or ", ".join(path.as_posix() for path in parse_update_sync_paths()),
        "checked_at": state.get("checked_at") or "尚未检查",
        "checking": state.get("checking") == "1",
        "update_available": state.get("update_available") == "1",
        "error": state.get("error") or "",
    }


def restart_wireguard():
    try:
        return run_command(["docker", "compose", "up", "-d", "--force-recreate", "wireguard"], timeout=180)
    except FileNotFoundError:
        return run_command(["docker-compose", "up", "-d", "--force-recreate", "wireguard"], timeout=180)


def current_admin_image():
    configured_image = os.environ.get("ADMIN_UPDATER_IMAGE", "").strip()
    if configured_image:
        return configured_image
    candidates = [
        os.environ.get("HOSTNAME", "").strip(),
        os.environ.get("ADMIN_CONTAINER_NAME", "vpn-admin").strip(),
        "vpn-admin",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            image = run_command(["docker", "inspect", candidate, "--format", "{{.Config.Image}}"], timeout=30)
            if image:
                return image
        except Exception:
            pass
    return "vpn-vpn-admin:latest"


def rebuild_admin():
    script = (
        "set -eu; "
        "mkdir -p /work/deploy; "
        "cd /work; "
        "sleep 2; "
        "{ "
        "docker compose stop vpn-admin || true; "
        "docker compose rm -sf vpn-admin || true; "
        "docker compose up -d --build --force-recreate --remove-orphans vpn-admin; "
        "} > /work/deploy/update-rebuild.log 2>&1"
    )
    try:
        run_command(["docker", "rm", "-f", "vpn-admin-updater"], timeout=30)
    except Exception:
        pass
    return run_command(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            "vpn-admin-updater",
            "-v",
            f"{VPN_DIR}:/work",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-w",
            "/work",
            "--entrypoint",
            "sh",
            current_admin_image(),
            "-c",
            script,
        ],
        timeout=120,
    )


def update_repo_dir_for_runner():
    try:
        return Path("/work") / UPDATE_REPO_DIR.relative_to(VPN_DIR)
    except ValueError:
        return Path("/work/wg-clash-admin")


def build_stable_update_script(branch, sync_paths):
    quoted_paths = " ".join(shlex.quote(path.as_posix()) for path in sync_paths)
    version_path = shlex.quote(safe_relative_path(UPDATE_VERSION_FILE).as_posix())
    return f"""
set -eu
LOG=/work/deploy/update-rebuild.log
mkdir -p /work/deploy /work/deploy/backups
exec > "$LOG" 2>&1
echo "update started at $(date)"
sleep 2
cd /work
ADMIN_SERVICE=vpn-admin
ADMIN_CONTAINER="${{ADMIN_CONTAINER_NAME:-vpn-admin}}"
COMPOSE_FILE=/work/docker-compose.yml
ENV_FILE=/work/.env
if [ -f "$ENV_FILE" ]; then
  ENV_ADMIN_CONTAINER="$(grep -E '^ADMIN_CONTAINER_NAME=' "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true)"
  ADMIN_CONTAINER="${{ENV_ADMIN_CONTAINER:-$ADMIN_CONTAINER}}"
fi
compose() {{
  if [ -f "$ENV_FILE" ]; then
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
  else
    docker compose -f "$COMPOSE_FILE" "$@"
  fi
}}
stop_admin() {{
  echo "stopping old admin service: $ADMIN_SERVICE"
  compose stop "$ADMIN_SERVICE" || true
  compose rm -sf "$ADMIN_SERVICE" || true
  docker rm -f "$ADMIN_CONTAINER" 2>/dev/null || true
}}
wait_admin_running() {{
  i=0
  while [ "$i" -lt 30 ]; do
    state="$(docker inspect "$ADMIN_CONTAINER" --format '{{{{.State.Status}}}}' 2>/dev/null || true)"
    if [ "$state" = "running" ]; then
      echo "admin container is running: $ADMIN_CONTAINER"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "admin container did not become running"
  docker ps -a --filter "name=$ADMIN_CONTAINER"
  compose logs --tail=120 "$ADMIN_SERVICE" || true
  return 1
}}
REPO_DIR={shlex.quote(str(update_repo_dir_for_runner()))}
REPO_URL={shlex.quote(UPDATE_REPO_URL)}
BRANCH={shlex.quote(branch)}
if [ ! -d "$REPO_DIR/.git" ]; then
  rm -rf "$REPO_DIR"
  mkdir -p "$(dirname "$REPO_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
fi
git -C "$REPO_DIR" -c safe.directory="$REPO_DIR" fetch --quiet origin
git -C "$REPO_DIR" -c safe.directory="$REPO_DIR" checkout "$BRANCH" || git -C "$REPO_DIR" -c safe.directory="$REPO_DIR" checkout -b "$BRANCH" "origin/$BRANCH"
git -C "$REPO_DIR" -c safe.directory="$REPO_DIR" pull --ff-only origin "$BRANCH"
echo "before sync version: $(cat /work/{version_path} 2>/dev/null || true)"
echo "target version: $(cat "$REPO_DIR/{version_path}" 2>/dev/null || true)"
stop_admin
BACKUP="/work/deploy/backups/update-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
for rel in {quoted_paths}; do
  src="$REPO_DIR/$rel"
  dst="/work/$rel"
  if [ ! -e "$src" ] && [ ! -L "$src" ]; then
    echo "missing sync path: $src"
    exit 1
  fi
  if [ -e "$dst" ] || [ -L "$dst" ]; then
    mkdir -p "$BACKUP/$(dirname "$rel")"
    cp -a "$dst" "$BACKUP/$rel"
  fi
  rm -rf "$dst"
  mkdir -p "$(dirname "$dst")"
  cp -a "$src" "$dst"
  echo "synced $rel"
done
echo "after sync version: $(cat /work/{version_path} 2>/dev/null || true)"
if grep -q "def merge_clash_config" /work/admin/app.py && grep -q "normalize_group_name" /work/admin/app.py; then
  echo "merge feature check: ok"
else
  echo "merge feature check: missing"
  exit 1
fi
echo "building fresh admin image"
compose build --no-cache "$ADMIN_SERVICE"
echo "starting fresh admin container"
compose up -d --force-recreate --remove-orphans "$ADMIN_SERVICE"
wait_admin_running
docker ps --filter "name=$ADMIN_CONTAINER"
echo "update finished at $(date)"
""".strip()


def start_stable_update_runner(branch, sync_paths):
    try:
        run_command(["docker", "rm", "-f", "vpn-admin-updater"], timeout=30)
    except Exception:
        pass
    return run_command(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            "vpn-admin-updater",
            "-v",
            f"{VPN_DIR}:/work",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-w",
            "/work",
            "--entrypoint",
            "sh",
            current_admin_image(),
            "-c",
            build_stable_update_script(branch, sync_paths),
        ],
        timeout=120,
    )


def wait_for_peer_files(peers, timeout=60):
    deadline = time.monotonic() + timeout
    target = PEER_ROOT / f"peer{peers}" / f"peer{peers}.conf"
    while time.monotonic() < deadline:
        if target.exists():
            return
        time.sleep(2)
    raise RuntimeError(f"等待 peer{peers} 配置生成超时")


def refresh_config():
    if not RUN_SCRIPT.exists():
        raise RuntimeError("run.sh 不存在")
    return run_command(["bash", str(RUN_SCRIPT)], timeout=180)


def valid_subscription_url(value):
    return bool(re.fullmatch(r"https?://[^\s]+", value or ""))


def unique_name(base, used_names):
    name = str(base or "node").strip() or "node"
    if name not in used_names:
        used_names.add(name)
        return name
    index = 2
    while f"{name}-{index}" in used_names:
        index += 1
    next_name = f"{name}-{index}"
    used_names.add(next_name)
    return next_name


def external_subscription_cache_key(source, suffix):
    url_hash = hashlib.sha1(source["url"].encode("utf-8")).hexdigest()[:12]
    return f"external-subscription:{source['id']}:{url_hash}:{suffix}"


def get_cached_external_subscription(source, allow_stale=False):
    redis_client = get_redis()
    cache_keys = [external_subscription_cache_key(source, "yaml")]
    if allow_stale:
        cache_keys.append(external_subscription_cache_key(source, "yaml-stale"))
    for cache_key in cache_keys:
        cached_text = redis_client.get(cache_key)
        if cached_text:
            return parse_external_subscription_text(cached_text)
    return None


def parse_external_subscription_text(text):
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise RuntimeError("订阅内容不是 YAML 对象")
    return data


def external_subscription_opener():
    if EXTERNAL_SUBSCRIPTION_PROXY:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler(
                {
                    "http": EXTERNAL_SUBSCRIPTION_PROXY,
                    "https": EXTERNAL_SUBSCRIPTION_PROXY,
                }
            )
        )
    return urllib.request.build_opener()


def log_external_subscription_failure(source, message, used_stale_cache):
    detail = f"{source['name']}: {message}"
    if used_stale_cache:
        detail += "；已回退到缓存订阅"
    log_system_action_once(
        "merge_subscription_skip",
        detail,
        False,
        cooldown_seconds=EXTERNAL_SUBSCRIPTION_FAILURE_LOG_COOLDOWN,
        scope=f"{source['id']}:{'stale' if used_stale_cache else 'live'}",
    )


def mark_external_subscription_success(source_id):
    with get_db().cursor() as cur:
        cur.execute(
            """
            UPDATE external_subscriptions
            SET consecutive_failures = 0,
                suspended = FALSE,
                last_error = '',
                last_failed_at = NULL,
                updated_at = NOW()
            WHERE id = %s
            """,
            (source_id,),
        )
    get_db().commit()


def mark_external_subscription_failure(source, message):
    row = query_one(
        """
        UPDATE external_subscriptions
        SET consecutive_failures = consecutive_failures + 1,
            last_error = %s,
            last_failed_at = NOW(),
            suspended = CASE
                WHEN consecutive_failures + 1 >= %s THEN TRUE
                ELSE suspended
            END,
            updated_at = NOW()
        WHERE id = %s
        RETURNING consecutive_failures, suspended
        """,
        (message[:1800], EXTERNAL_SUBSCRIPTION_MAX_FAILURES, source["id"]),
    )
    get_db().commit()
    failures = row["consecutive_failures"] if row else EXTERNAL_SUBSCRIPTION_MAX_FAILURES
    suspended = bool(row["suspended"]) if row else False
    if suspended and failures >= EXTERNAL_SUBSCRIPTION_MAX_FAILURES:
        log_system_action_once(
            "external_subscription_suspended",
            f"{source['name']}: 连续失败 {failures} 次，已自动暂停拉取。最后错误：{message}",
            False,
            cooldown_seconds=60 * 60 * 24,
            scope=str(source["id"]),
        )
    return failures, suspended


def fetch_external_subscription(source):
    redis_client = get_redis()
    hot_cache_key = external_subscription_cache_key(source, "yaml")
    stale_cache_key = external_subscription_cache_key(source, "yaml-stale")
    cached_config = get_cached_external_subscription(source)
    if cached_config is not None:
        return cached_config

    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": f"wg-clash-admin/{read_version(local_version_file()) or 'local'}"},
    )
    opener = external_subscription_opener()
    try:
        with opener.open(request, timeout=EXTERNAL_SUBSCRIPTION_TIMEOUT) as response:
            status = getattr(response, "status", 200)
            if status >= 400:
                raise RuntimeError(f"HTTP {status}")
            content = response.read(EXTERNAL_SUBSCRIPTION_MAX_BYTES + 1)
            if len(content) > EXTERNAL_SUBSCRIPTION_MAX_BYTES:
                raise RuntimeError("订阅文件过大")
        text = content.decode("utf-8")
        data = parse_external_subscription_text(text)
    except Exception as exc:
        mark_external_subscription_failure(source, str(exc))
        stale_text = redis_client.get(stale_cache_key)
        if stale_text:
            log_external_subscription_failure(source, str(exc), True)
            return parse_external_subscription_text(stale_text)
        log_external_subscription_failure(source, str(exc), False)
        raise

    redis_client.setex(hot_cache_key, max(1, EXTERNAL_SUBSCRIPTION_CACHE_TTL), text)
    redis_client.setex(stale_cache_key, max(1, EXTERNAL_SUBSCRIPTION_STALE_TTL), text)
    mark_external_subscription_success(source["id"])
    return data


def rewrite_rule_target(rule, name_map):
    if not isinstance(rule, str):
        return rule
    parts = rule.split(",")
    for index in range(len(parts) - 1, -1, -1):
        target = parts[index].strip()
        if target in name_map:
            parts[index] = parts[index].replace(target, name_map[target], 1)
            return ",".join(parts)
    return rule


def append_unique(target, values):
    for value in values:
        if value and value not in target:
            target.append(value)


def normalize_group_name(name):
    return re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]+", "", str(name or "")).lower()


def resolve_external_group_entries(name, external_group_map, proxy_name_map, seen=None):
    if name in proxy_name_map:
        return [proxy_name_map[name]]
    if name in ("DIRECT", "REJECT"):
        return [name]
    if name not in external_group_map:
        return []
    seen = seen or set()
    if name in seen:
        return []
    seen.add(name)
    entries = []
    for item in external_group_map[name].get("proxies") or []:
        entries.extend(resolve_external_group_entries(item, external_group_map, proxy_name_map, seen))
    seen.remove(name)
    return entries


def merge_clash_config(base_config, external_configs):
    base_config = base_config or {}
    base_proxies = base_config.setdefault("proxies", [])
    base_groups = base_config.setdefault("proxy-groups", [])
    base_rules = base_config.setdefault("rules", [])
    used_names = {
        item.get("name")
        for item in list(base_proxies) + list(base_groups)
        if isinstance(item, dict) and item.get("name")
    }
    base_group_map = {
        group["name"]: group
        for group in base_groups
        if isinstance(group, dict) and group.get("name")
    }
    normalized_base_group_map = {}
    for group in base_groups:
        if isinstance(group, dict) and group.get("name"):
            normalized_base_group_map.setdefault(normalize_group_name(group["name"]), group)
    selector_name = "🚀 节点选择"
    selector = base_group_map.get(selector_name)
    if selector is None:
        selector = normalized_base_group_map.get(normalize_group_name(selector_name))
    selector_entries = selector.setdefault("proxies", []) if selector is not None else None

    for source, external in external_configs:
        prefix = re.sub(r"[^A-Za-z0-9_.-]+", "-", source["name"]).strip("-") or f"sub-{source['id']}"
        proxy_name_map = {}
        imported_proxy_names = []
        for proxy in external.get("proxies") or []:
            if not isinstance(proxy, dict) or not proxy.get("name"):
                continue
            copied_proxy = dict(proxy)
            next_name = unique_name(f"{prefix}-{proxy['name']}", used_names)
            proxy_name_map[proxy["name"]] = next_name
            copied_proxy["name"] = next_name
            base_proxies.append(copied_proxy)
            imported_proxy_names.append(next_name)

        external_groups = [group for group in external.get("proxy-groups") or [] if isinstance(group, dict) and group.get("name")]
        external_group_map = {group["name"]: group for group in external_groups}
        merged_selector_entries = []

        for group in external_groups:
            base_group = base_group_map.get(group["name"]) or normalized_base_group_map.get(normalize_group_name(group["name"]))
            if base_group is None:
                continue
            merged_entries = []
            for item in group.get("proxies") or []:
                merged_entries.extend(resolve_external_group_entries(item, external_group_map, proxy_name_map))
            append_unique(base_group.setdefault("proxies", []), merged_entries)
            if selector is not None and base_group is selector:
                merged_selector_entries.extend(merged_entries)

        if selector_entries is not None and not merged_selector_entries:
            append_unique(selector_entries, imported_proxy_names)

        rule_target_map = dict(proxy_name_map)
        for group in external_groups:
            base_group = base_group_map.get(group["name"]) or normalized_base_group_map.get(normalize_group_name(group["name"]))
            if base_group is not None:
                rule_target_map[group["name"]] = base_group["name"]
            elif selector_entries is not None:
                rule_target_map[group["name"]] = selector["name"]
        for rule in external.get("rules") or []:
            base_rules.append(rewrite_rule_target(rule, rule_target_map))

    return base_config


def build_subscription_yaml():
    with CLASH_FILE.open("r", encoding="utf-8") as file:
        base_config = yaml.safe_load(file) or {}
    sources = query_all(
        """
        SELECT id, name, url, consecutive_failures, suspended, last_error, last_failed_at
        FROM external_subscriptions
        WHERE is_active = TRUE
        ORDER BY id
        """
    )
    external_configs = []
    for source in sources:
        if source.get("suspended"):
            cached_config = get_cached_external_subscription(source, allow_stale=True)
            if cached_config is not None:
                external_configs.append((source, cached_config))
            continue
        try:
            external_configs.append((source, fetch_external_subscription(source)))
        except Exception:
            continue
    if external_configs:
        base_config = merge_clash_config(base_config, external_configs)
    return yaml.safe_dump(base_config, allow_unicode=True, sort_keys=False)


def apply_settings_background(lock_id, actor_user_id, server_url, port, peers, local_node_prefix):
    detail = f"SERVERURL={server_url}, SERVERPORT={port}, PEERS={peers}, LOCAL_NODE_PREFIX={local_node_prefix}"
    with app.app_context():
        try:
            update_compose(server_url, port, peers, local_node_prefix)
            update_peer_endpoints(server_url, port)
            set_setting("server_url", server_url)
            set_setting("server_port", port)
            set_setting("peers", peers)
            set_setting("local_node_prefix", local_node_prefix)
            restart_wireguard()
            refresh_config()
            with get_db().cursor() as cur:
                cur.execute(
                    "INSERT INTO operation_logs (actor_user_id, action, detail, success) VALUES (%s, %s, %s, %s)",
                    (actor_user_id, "apply_settings_async", detail, True),
                )
            get_db().commit()
        except Exception as exc:
            with get_db().cursor() as cur:
                cur.execute(
                    "INSERT INTO operation_logs (actor_user_id, action, detail, success) VALUES (%s, %s, %s, %s)",
                    (actor_user_id, "apply_settings_async", f"{detail}; error={exc}", False),
                )
            get_db().commit()
        finally:
            release_operation_lock(lock_id)


def copy_item(src, dst, backup_root):
    if not src.exists():
        raise RuntimeError(f"待同步文件不存在：{src}")
    backup_dst = backup_root / dst.relative_to(VPN_DIR)
    if dst.exists() or dst.is_symlink():
        backup_dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.is_dir() and not dst.is_symlink():
            shutil.copytree(dst, backup_dst, symlinks=True)
            shutil.rmtree(dst)
        else:
            shutil.copy2(dst, backup_dst)
            dst.unlink()
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir() and not src.is_symlink():
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst)


def sync_update_files():
    backup_root = VPN_DIR / "deploy" / "backups" / f"update-{now_local().strftime('%Y%m%d-%H%M%S')}"
    copied = []
    for rel_path in parse_update_sync_paths():
        src = UPDATE_REPO_DIR / rel_path
        dst = VPN_DIR / rel_path
        copy_item(src, dst, backup_root)
        copied.append(rel_path.as_posix())
    return copied, backup_root


def version_update_background(lock_id, actor_user_id):
    with app.app_context():
        before = optional_repo_git_command(["rev-parse", "--short", "HEAD"], timeout=8) or "unknown"
        try:
            ensure_update_repo()
            branch = get_update_branch()
            sync_paths = parse_update_sync_paths()
            runner_id = start_stable_update_runner(branch, sync_paths)
            write_update_state(update_available="0", checking="1", error="")
            detail = (
                f"stable updater started; before={before}; branch={branch}; "
                f"sync_paths={','.join(path.as_posix() for path in sync_paths)}; runner={runner_id}"
            )
            with get_db().cursor() as cur:
                cur.execute(
                    "INSERT INTO operation_logs (actor_user_id, action, detail, success) VALUES (%s, %s, %s, %s)",
                    (actor_user_id, "version_update", detail[:1800], True),
                )
            get_db().commit()
        except Exception as exc:
            with get_db().cursor() as cur:
                cur.execute(
                    "INSERT INTO operation_logs (actor_user_id, action, detail, success) VALUES (%s, %s, %s, %s)",
                    (actor_user_id, "version_update", str(exc)[:1800], False),
                )
            get_db().commit()
        finally:
            release_operation_lock(lock_id)


def require_login():
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    if not user_id or not session_id:
        return None
    cache_key = f"session:{session_id}"
    cached_id = get_redis().get(cache_key)
    if cached_id != str(user_id):
        session.clear()
        return None
    user = query_one("SELECT id, username, role, is_active FROM users WHERE id = %s", (user_id,))
    if not user or not user["is_active"]:
        session.clear()
        return None
    get_redis().expire(cache_key, SESSION_TTL_SECONDS)
    g.user = user
    return user


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(24)
        session["csrf_token"] = token
    return token


def verify_csrf():
    token = request.form.get("csrf_token", "")
    if not hmac.compare_digest(token, session.get("csrf_token", "")):
        raise RuntimeError("CSRF 校验失败，请刷新页面后重试")


def require_admin():
    if getattr(g, "user", None) is None or g.user["role"] != "admin":
        abort(403)


@app.before_request
def load_user():
    if request.endpoint in {"login", "subscription", "static"}:
        return
    if not require_login():
        return redirect(url_for("login"))


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token,
        "current_user": getattr(g, "user", None),
        "format_local_datetime": format_local_datetime,
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_one("SELECT * FROM users WHERE username = %s", (username,))
        if user and user["is_active"] and verify_password(password, user["password_hash"]):
            sid = secrets.token_urlsafe(32)
            get_redis().setex(f"session:{sid}", SESSION_TTL_SECONDS, str(user["id"]))
            session.clear()
            session["user_id"] = user["id"]
            session["session_id"] = sid
            session["csrf_token"] = secrets.token_urlsafe(24)
            return redirect(url_for("dashboard"))
        flash("账号或密码不正确", "error")
    return render_template("login.html", asset_version=read_version(local_version_file()) or str(APP_STARTED_AT))


@app.route("/logout", methods=["POST"])
def logout():
    verify_csrf()
    sid = session.get("session_id")
    if sid:
        get_redis().delete(f"session:{sid}")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    require_admin()
    try:
        log_page = max(1, int(request.args.get("log_page", "1") or "1"))
    except ValueError:
        log_page = 1
    log_per_page = max(1, int(env("LOG_PER_PAGE", "6")))
    log_offset = (log_page - 1) * log_per_page
    runtime = read_runtime_config()
    settings = {
        "server_url": get_setting("server_url", runtime["server_url"]),
        "server_port": int(get_setting("server_port", runtime["server_port"])),
        "peers": int(get_setting("peers", runtime["peers"])),
        "local_node_prefix": get_setting("local_node_prefix", runtime["local_node_prefix"]),
    }
    users = query_all("SELECT id, username, role, is_active, sub_token, created_at, updated_at FROM users ORDER BY id")
    for user in users:
        user["subscription_url"] = url_for("subscription", token=user["sub_token"], _external=True) if user.get("sub_token") else ""
    external_subscriptions = query_all(
        """
        SELECT id, name, url, is_active, consecutive_failures, suspended, last_error, last_failed_at, created_at, updated_at
        FROM external_subscriptions
        ORDER BY id
        """
    )
    log_total_row = query_one("SELECT COUNT(*) AS total FROM operation_logs")
    log_total = log_total_row["total"] if log_total_row else 0
    log_total_pages = max(1, (log_total + log_per_page - 1) // log_per_page)
    if log_page > log_total_pages:
        log_page = log_total_pages
        log_offset = (log_page - 1) * log_per_page
    logs = query_all(
        """
        SELECT l.*, u.username
        FROM operation_logs l
        LEFT JOIN users u ON u.id = l.actor_user_id
        ORDER BY l.created_at DESC
        LIMIT %s OFFSET %s
        """,
        (log_per_page, log_offset),
    )
    log_window = {1, log_total_pages, log_page - 1, log_page, log_page + 1}
    log_pages = [page for page in sorted(log_window) if 1 <= page <= log_total_pages]
    log_start = log_offset + 1 if log_total else 0
    log_end = min(log_offset + len(logs), log_total)
    return render_template(
        "dashboard.html",
        runtime=runtime,
        settings=settings,
        users=users,
        external_subscriptions=external_subscriptions,
        logs=logs,
        log_page=log_page,
        log_pages=log_pages,
        log_start=log_start,
        log_end=log_end,
        log_per_page=log_per_page,
        log_total_pages=log_total_pages,
        log_total=log_total,
        version=get_version_info(),
        app_started_at=APP_STARTED_AT,
        asset_version=read_version(local_version_file()) or str(APP_STARTED_AT),
    )


@app.route("/settings/apply", methods=["POST"])
def apply_settings():
    require_admin()
    verify_csrf()
    try:
        server_url = request.form.get("server_url", "").strip()
        local_node_prefix = request.form.get("local_node_prefix", "").strip() or "peer"
        port = int(request.form.get("server_port", "0"))
        peers = int(request.form.get("peers", "0"))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", server_url):
            raise ValueError("公网地址格式不合法")
        if not re.fullmatch(r"[\w.\-\u4e00-\u9fa5]{1,24}", local_node_prefix):
            raise ValueError("节点名前缀必须是 1-24 位中文、字母、数字、点、下划线或横线")
        validate_port(port)
        validate_peers(peers)
        lock_id = acquire_operation_lock()
        if not lock_id:
            raise RuntimeError("已有刷新或切换任务正在执行，请稍后再试")
        worker = threading.Thread(
            target=apply_settings_background,
            args=(lock_id, g.user["id"], server_url, port, peers, local_node_prefix),
            daemon=True,
        )
        worker.start()
        flash("切换任务已提交，后台正在执行。请 10 秒后刷新页面或重试订阅。", "success")
    except Exception as exc:
        log_action("apply_settings_async_submit", str(exc), False)
        flash(str(exc), "error")
    return redirect(url_for("dashboard"))


@app.route("/external-subscriptions/create", methods=["POST"])
def create_external_subscription():
    require_admin()
    verify_csrf()
    try:
        name = request.form.get("name", "").strip()
        url = request.form.get("url", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.\-\u4e00-\u9fa5]{2,32}", name):
            raise ValueError("订阅名称必须是 2-32 位中文、字母、数字、点、下划线或横线")
        if not valid_subscription_url(url):
            raise ValueError("订阅链接必须以 http:// 或 https:// 开头，且不能包含空格")
        with get_db().cursor() as cur:
            cur.execute(
                "INSERT INTO external_subscriptions (name, url) VALUES (%s, %s)",
                (name, url),
            )
        get_db().commit()
        log_action("create_external_subscription", name)
        flash("外部订阅源已添加", "success")
    except Exception as exc:
        get_db().rollback()
        log_action("create_external_subscription", str(exc), False)
        flash(str(exc), "error")
    return redirect(url_for("dashboard") + "#subscriptions")


@app.route("/external-subscriptions/<int:source_id>/toggle", methods=["POST"])
def toggle_external_subscription(source_id):
    require_admin()
    verify_csrf()
    with get_db().cursor() as cur:
        cur.execute(
            """
            UPDATE external_subscriptions
            SET is_active = NOT is_active,
                consecutive_failures = CASE WHEN NOT is_active THEN 0 ELSE consecutive_failures END,
                suspended = CASE WHEN NOT is_active THEN FALSE ELSE suspended END,
                last_error = CASE WHEN NOT is_active THEN '' ELSE last_error END,
                last_failed_at = CASE WHEN NOT is_active THEN NULL ELSE last_failed_at END,
                updated_at = NOW()
            WHERE id = %s
            """,
            (source_id,),
        )
    get_db().commit()
    log_action("toggle_external_subscription", str(source_id))
    return redirect(url_for("dashboard") + "#subscriptions")


@app.route("/external-subscriptions/<int:source_id>/resume", methods=["POST"])
def resume_external_subscription(source_id):
    require_admin()
    verify_csrf()
    with get_db().cursor() as cur:
        cur.execute(
            """
            UPDATE external_subscriptions
            SET is_active = TRUE,
                consecutive_failures = 0,
                suspended = FALSE,
                last_error = '',
                last_failed_at = NULL,
                updated_at = NOW()
            WHERE id = %s
            """,
            (source_id,),
        )
    get_db().commit()
    log_action("resume_external_subscription", str(source_id))
    flash("订阅源已恢复，下次拉取订阅时会重新尝试合并。", "success")
    return redirect(url_for("dashboard") + "#subscriptions")


@app.route("/external-subscriptions/<int:source_id>/delete", methods=["POST"])
def delete_external_subscription(source_id):
    require_admin()
    verify_csrf()
    with get_db().cursor() as cur:
        cur.execute("DELETE FROM external_subscriptions WHERE id = %s", (source_id,))
    get_db().commit()
    log_action("delete_external_subscription", str(source_id))
    return redirect(url_for("dashboard") + "#subscriptions")


@app.route("/refresh", methods=["POST"])
def refresh():
    require_admin()
    verify_csrf()
    try:
        with operation_lock():
            refresh_config()
        log_action("refresh_config", "run.sh")
        flash("配置刷新完成", "success")
    except Exception as exc:
        log_action("refresh_config", str(exc), False)
        flash(str(exc), "error")
    return redirect(url_for("dashboard"))


@app.route("/version/update", methods=["POST"])
def update_version():
    require_admin()
    verify_csrf()
    try:
        version = get_version_info()
        if not version["update_available"]:
            raise RuntimeError("当前没有可更新版本，请先检查版本或等待定时检查完成")
        lock_id = acquire_operation_lock()
        if not lock_id:
            raise RuntimeError("已有刷新、切换或更新任务正在执行，请稍后再试")
        worker = threading.Thread(
            target=version_update_background,
            args=(lock_id, g.user["id"]),
            daemon=True,
        )
        worker.start()
        return render_template(
            "updating.html",
            target_version=version["remote_version"],
            asset_version=read_version(local_version_file()) or str(APP_STARTED_AT),
        )
    except Exception as exc:
        log_action("version_update_submit", str(exc), False)
        flash(str(exc), "error")
    return redirect(url_for("dashboard"))


@app.route("/version/check", methods=["POST"])
def check_version():
    require_admin()
    verify_csrf()
    try:
        if maybe_start_update_check(force=True):
            flash("版本检查已开始，请稍后刷新页面查看结果。", "success")
        else:
            flash("已有版本检查任务正在执行，请稍后刷新页面。", "success")
    except Exception as exc:
        log_action("version_check_submit", str(exc), False)
        flash(str(exc), "error")
    return redirect(url_for("dashboard"))


@app.route("/version/ping")
def version_ping():
    require_admin()
    return jsonify(
        {
            "started_at": APP_STARTED_AT,
            "local_version": read_version(local_version_file()) or "未安装版本",
        }
    )


@app.route("/users/create", methods=["POST"])
def create_user():
    require_admin()
    verify_csrf()
    try:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            raise ValueError("用户名必须是 3-32 位字母、数字、点、下划线或横线")
        if len(password) < 8:
            raise ValueError("密码至少 8 位")
        if role not in {"admin", "user"}:
            raise ValueError("角色只能是 admin 或 user")
        token = generate_token()
        with get_db().cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, role, sub_token, sub_token_hash) VALUES (%s, %s, %s, %s, %s)",
                (username, hash_password(password), role, token, hash_token(token)),
            )
        get_db().commit()
        log_action("create_user", username)
        flash(f"用户已创建，订阅 token：{token}", "success")
    except Exception as exc:
        get_db().rollback()
        log_action("create_user", str(exc), False)
        flash(str(exc), "error")
    return redirect(url_for("dashboard"))


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
def toggle_user(user_id):
    require_admin()
    verify_csrf()
    if user_id == g.user["id"]:
        flash("不能禁用当前登录用户", "error")
        return redirect(url_for("dashboard"))
    with get_db().cursor() as cur:
        cur.execute("UPDATE users SET is_active = NOT is_active, updated_at = NOW() WHERE id = %s", (user_id,))
    get_db().commit()
    log_action("toggle_user", str(user_id))
    return redirect(url_for("dashboard"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
def reset_password(user_id):
    require_admin()
    verify_csrf()
    password = request.form.get("password", "")
    if len(password) < 8:
        flash("密码至少 8 位", "error")
        return redirect(url_for("dashboard"))
    with get_db().cursor() as cur:
        cur.execute("UPDATE users SET password_hash = %s, updated_at = NOW() WHERE id = %s", (hash_password(password), user_id))
    get_db().commit()
    log_action("reset_password", str(user_id))
    flash("密码已重置", "success")
    return redirect(url_for("dashboard"))


@app.route("/users/<int:user_id>/token", methods=["POST"])
def reset_token(user_id):
    require_admin()
    verify_csrf()
    token = generate_token()
    old_user = query_one("SELECT username, sub_token_hash FROM users WHERE id = %s", (user_id,))
    with get_db().cursor() as cur:
        cur.execute("UPDATE users SET sub_token = %s, sub_token_hash = %s, updated_at = NOW() WHERE id = %s", (token, hash_token(token), user_id))
    get_db().commit()
    if old_user and old_user.get("sub_token_hash"):
        get_redis().delete(f"sub-token:{old_user['sub_token_hash']}")
    get_redis().delete(f"sub-token:{hash_token(token)}")
    log_action("reset_token", str(user_id))
    flash(f"新订阅 token：{token}", "success")
    return redirect(url_for("dashboard"))


@app.route("/file/clash.yaml")
def subscription():
    token = request.args.get("token", "")
    if not token:
        return Response("missing token\n", status=401, mimetype="text/plain")
    digest = hash_token(token)
    cache_key = f"sub-token:{digest}"
    cached = get_redis().get(cache_key)
    if cached is None:
        user = query_one("SELECT id FROM users WHERE sub_token_hash = %s AND is_active = TRUE", (digest,))
        if not user:
            get_redis().setex(cache_key, 60, "0")
            return Response("invalid token\n", status=403, mimetype="text/plain")
        get_redis().setex(cache_key, 300, "1")
    elif cached != "1":
        return Response("invalid token\n", status=403, mimetype="text/plain")
    if not CLASH_FILE.exists():
        return Response("clash config not generated\n", status=404, mimetype="text/plain")
    try:
        content = build_subscription_yaml()
    except Exception as exc:
        log_system_action("build_subscription", str(exc), False)
        return send_file(CLASH_FILE, mimetype="text/yaml; charset=utf-8", as_attachment=False, download_name="clash-config.yaml")
    return Response(
        content,
        mimetype="text/yaml; charset=utf-8",
        headers={"Content-Disposition": "inline; filename=clash-config.yaml"},
    )


if __name__ == "__main__":
    app.run(
        host=env("HOST", "127.0.0.1"),
        port=int(env("PORT", "8088")),
        debug=False,
        threaded=True,
        use_reloader=False,
    )
