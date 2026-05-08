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
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import psycopg
import redis
from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
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


app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)


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
        "docker compose up -d --build vpn-admin > /work/deploy/update-rebuild.log 2>&1"
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
    return render_template("login.html")


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
    runtime = read_runtime_config()
    settings = {
        "server_url": get_setting("server_url", runtime["server_url"]),
        "server_port": int(get_setting("server_port", runtime["server_port"])),
        "peers": int(get_setting("peers", runtime["peers"])),
    }
    users = query_all("SELECT id, username, role, is_active, sub_token, created_at, updated_at FROM users ORDER BY id")
    for user in users:
        user["subscription_url"] = url_for("subscription", token=user["sub_token"], _external=True) if user.get("sub_token") else ""
    logs = query_all(
        """
        SELECT l.*, u.username
        FROM operation_logs l
        LEFT JOIN users u ON u.id = l.actor_user_id
        ORDER BY l.created_at DESC
        LIMIT 12
        """
    )
    return render_template(
        "dashboard.html",
        runtime=runtime,
        settings=settings,
        users=users,
        logs=logs,
        version=get_version_info(),
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
        flash("版本更新任务已提交，后台会拉取源码、同步运行目录并重建后台容器。请约 30 秒后刷新页面。", "success")
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
    return send_file(CLASH_FILE, mimetype="text/yaml; charset=utf-8", as_attachment=False, download_name="clash-config.yaml")


if __name__ == "__main__":
    app.run(
        host=env("HOST", "127.0.0.1"),
        port=int(env("PORT", "8088")),
        debug=False,
        threaded=True,
        use_reloader=False,
    )
