#!/usr/bin/env python3
import base64
import hashlib
import hmac
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

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
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
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
    return {"server_url": server_url, "server_port": server_port, "peers": peers}


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
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.{stamp}.bak")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def update_compose(server_url, port, peers):
    update_env_file({
        "SERVERURL": server_url,
        "SERVERPORT": str(port),
        "PEERS": str(peers),
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
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
                checked_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
    return {
        "local_version": state.get("local_version") or read_version(local_version_file()) or "未安装版本",
        "remote_version": state.get("remote_version") or "",
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


def fetch_external_subscription(source):
    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": f"wg-clash-admin/{read_version(local_version_file()) or 'local'}"},
    )
    with urllib.request.urlopen(request, timeout=EXTERNAL_SUBSCRIPTION_TIMEOUT) as response:
        status = getattr(response, "status", 200)
        if status >= 400:
            raise RuntimeError(f"HTTP {status}")
        content = response.read(EXTERNAL_SUBSCRIPTION_MAX_BYTES + 1)
        if len(content) > EXTERNAL_SUBSCRIPTION_MAX_BYTES:
            raise RuntimeError("订阅文件过大")
    data = yaml.safe_load(content.decode("utf-8")) or {}
    if not isinstance(data, dict):
        raise RuntimeError("订阅内容不是 YAML 对象")
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
    selector = next((group for group in base_groups if isinstance(group, dict) and group.get("name") == "🚀 节点选择"), None)
    selector_entries = selector.setdefault("proxies", []) if selector is not None else None

    for source, external in external_configs:
        prefix = re.sub(r"[^A-Za-z0-9_.-]+", "-", source["name"]).strip("-") or f"sub-{source['id']}"
        name_map = {}
        imported_proxy_names = []
        for proxy in external.get("proxies") or []:
            if not isinstance(proxy, dict) or not proxy.get("name"):
                continue
            copied_proxy = dict(proxy)
            next_name = unique_name(f"{prefix}-{proxy['name']}", used_names)
            name_map[proxy["name"]] = next_name
            copied_proxy["name"] = next_name
            base_proxies.append(copied_proxy)
            imported_proxy_names.append(next_name)

        external_groups = [group for group in external.get("proxy-groups") or [] if isinstance(group, dict) and group.get("name")]
        for group in external_groups:
            name_map[group["name"]] = unique_name(f"{prefix}-{group['name']}", used_names)

        for group in external_groups:
            if not isinstance(group, dict) or not group.get("name"):
                continue
            copied_group = dict(group)
            copied_group["name"] = name_map[group["name"]]
            copied_group["proxies"] = [name_map.get(item, item) for item in group.get("proxies") or []]
            base_groups.append(copied_group)

        if selector_entries is not None:
            target_names = [name_map.get(group.get("name")) for group in external_groups]
            target_names = [name for name in target_names if name] or imported_proxy_names
            selector_entries.extend(name for name in target_names if name not in selector_entries)

        for rule in external.get("rules") or []:
            base_rules.append(rewrite_rule_target(rule, name_map))

    return base_config


def build_subscription_yaml():
    with CLASH_FILE.open("r", encoding="utf-8") as file:
        base_config = yaml.safe_load(file) or {}
    sources = query_all("SELECT id, name, url FROM external_subscriptions WHERE is_active = TRUE ORDER BY id")
    external_configs = []
    failures = []
    for source in sources:
        try:
            external_configs.append((source, fetch_external_subscription(source)))
        except Exception as exc:
            failures.append(f"{source['name']}: {exc}")
    if failures:
        log_system_action("merge_subscription_skip", "; ".join(failures), False)
    if external_configs:
        base_config = merge_clash_config(base_config, external_configs)
    return yaml.safe_dump(base_config, allow_unicode=True, sort_keys=False)


def apply_settings_background(lock_id, actor_user_id, server_url, port, peers):
    detail = f"SERVERURL={server_url}, SERVERPORT={port}, PEERS={peers}"
    with app.app_context():
        try:
            update_compose(server_url, port, peers)
            update_peer_endpoints(server_url, port)
            set_setting("server_url", server_url)
            set_setting("server_port", port)
            set_setting("peers", peers)
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
    backup_root = VPN_DIR / "deploy" / "backups" / f"update-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
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
            repo_git_command(["fetch", "--quiet", "origin"], timeout=180)
            if not optional_repo_git_command(["rev-parse", "--verify", branch], timeout=8):
                repo_git_command(["checkout", "-b", branch, f"origin/{branch}"], timeout=120)
            else:
                repo_git_command(["checkout", branch], timeout=120)
            pull_output = repo_git_command(["pull", "--ff-only", "origin", branch], timeout=300)
            copied, backup_root = sync_update_files()
            after = optional_repo_git_command(["rev-parse", "--short", "HEAD"], timeout=8) or "unknown"
            rebuild_output = rebuild_admin()
            write_update_state(**check_remote_version())
            detail = (
                f"{before} -> {after}; branch={branch}; "
                f"{pull_output or 'already up to date'}; copied={','.join(copied)}; "
                f"backup={backup_root}; {rebuild_output or 'admin rebuilt'}"
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
    return {"csrf_token": csrf_token, "current_user": getattr(g, "user", None)}


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
    }
    users = query_all("SELECT id, username, role, is_active, sub_token, created_at, updated_at FROM users ORDER BY id")
    for user in users:
        user["subscription_url"] = url_for("subscription", token=user["sub_token"], _external=True) if user.get("sub_token") else ""
    external_subscriptions = query_all(
        "SELECT id, name, url, is_active, created_at, updated_at FROM external_subscriptions ORDER BY id"
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
        port = int(request.form.get("server_port", "0"))
        peers = int(request.form.get("peers", "0"))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", server_url):
            raise ValueError("公网地址格式不合法")
        validate_port(port)
        validate_peers(peers)
        lock_id = acquire_operation_lock()
        if not lock_id:
            raise RuntimeError("已有刷新或切换任务正在执行，请稍后再试")
        worker = threading.Thread(
            target=apply_settings_background,
            args=(lock_id, g.user["id"], server_url, port, peers),
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
        cur.execute("UPDATE external_subscriptions SET is_active = NOT is_active, updated_at = NOW() WHERE id = %s", (source_id,))
    get_db().commit()
    log_action("toggle_external_subscription", str(source_id))
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
