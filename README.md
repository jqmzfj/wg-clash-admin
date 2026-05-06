# WireGuard Clash 管理后台

这是一个轻量 Docker Web 后台，用于管理 `linuxserver/wireguard` 容器，并生成带 token 鉴权的 Clash 订阅文件。

主要功能：

- 登录后台
- 创建、禁用、启用用户
- 重置用户密码
- 重置订阅 token，旧 token 立即失效
- 一键复制每个用户的订阅链接
- 修改 WireGuard 公网地址 `SERVERURL`
- 修改 WireGuard 外网 UDP 端口 `SERVERPORT`
- 修改 WireGuard 客户端数量 `PEERS`
- 异步重建 WireGuard 容器
- 执行 `run.sh` 刷新 Clash 配置

## 目录说明

```text
.
├── admin/                 # Web 后台代码、模板、样式、Dockerfile
├── docker-compose.yml     # WireGuard 和后台服务编排
├── generate_clash_yaml.py # 从 WireGuard peer 配置生成 Clash 配置
├── run.sh                 # 刷新 Clash 配置的脚本
├── .env.example           # 环境变量示例，复制为 .env 后使用
├── .gitignore             # 排除运行态和敏感文件
└── vpn-config/            # WireGuard 运行生成的配置目录，不应提交
```

## 依赖条件

服务器需要具备：

- Docker
- Docker Compose v2
- Python 不需要在宿主机安装，后台在容器内运行
- 已有 PostgreSQL 服务
- 已有 Redis 服务

本项目默认**不会启动 PostgreSQL 和 Redis 容器**。这样更省内存，也方便复用服务器上已有的数据库和 Redis。

## 第一步：准备 PostgreSQL

后台会自动创建数据表，但不会自动创建数据库本身。请先创建数据库，例如：

```bash
createdb vpn_admin
```

如果 PostgreSQL 在 Docker 中运行，可以类似这样执行：

```bash
docker exec -it pgsql psql -U 你的PG用户 -d 默认数据库 -c "CREATE DATABASE vpn_admin;"
```

如果提示数据库已存在，可以忽略。

## 第二步：准备 Redis

Redis 用于：

- 保存登录会话
- 保存任务锁，避免重复切换配置
- 缓存订阅 token 校验结果

建议 Redis 设置密码。如果 Redis 没有密码，`REDIS_URL` 可以写成：

```text
redis://127.0.0.1:6379/0
```

如果 Redis 有密码，写成：

```text
redis://:你的Redis密码@127.0.0.1:6379/0
```

## 第三步：配置环境变量

复制示例文件：

```bash
cp .env.example .env
```

编辑 `.env`：

```bash
vim .env
```

最少必须修改这些参数：

```text
APP_SECRET=一段足够长的随机字符串
DATABASE_URL=postgresql://用户名:密码@127.0.0.1:5432/vpn_admin
REDIS_URL=redis://:Redis密码@127.0.0.1:6379/0
ADMIN_PASSWORD=后台管理员初始密码
SERVERURL=你的服务器公网IP或域名
SERVERPORT=WireGuard外网UDP端口
PEERS=客户端数量
```

`.env.example` 中每个参数都带有中文注释，可按需调整。

## 环境变量完整说明

### 基础安全配置

`APP_SECRET`

Flask 会话加密密钥。必须改成足够长的随机字符串，建议 32 位以上。不要使用示例值。

`ADMIN_USERNAME`

首次初始化时创建的管理员账号。默认是 `admin`。用户创建后，再修改这个变量不会自动改名。

`ADMIN_PASSWORD`

首次初始化时创建的管理员密码。用户创建后，再修改这个变量不会自动改密码。需要改密码时请登录后台，在账号管理里修改。

### PostgreSQL / Redis

`DATABASE_URL`

PostgreSQL 连接地址。

格式：

```text
postgresql://用户名:密码@主机:端口/数据库名
```

示例：

```text
postgresql://vpn_admin:strong_password@127.0.0.1:5432/vpn_admin
```

`REDIS_URL`

Redis 连接地址。

有密码：

```text
redis://:redis_password@127.0.0.1:6379/0
```

无密码：

```text
redis://127.0.0.1:6379/0
```

### 后台 Web 服务

`HOST`

后台监听地址。容器内通常保持 `0.0.0.0`。

`PORT`

后台监听端口。默认 `19090`。如果使用 `ADMIN_NETWORK_MODE=host`，这个端口会直接监听在服务器宿主机上。

`VPN_DIR`

容器内项目目录。默认 `/app/vpn`，通常不用改。

`URL_PREFIX`

后台访问路径前缀。默认：

```text
/sub/clash
```

后台首页地址就是：

```text
http://服务器IP:19090/sub/clash
```

如果你想让后台在根路径访问，可以设置为空：

```text
URL_PREFIX=
```

`STARTUP_WAIT_SECONDS`

后台启动时等待 PostgreSQL 和 Redis 可连接的最长秒数。默认 `90`。

`ADMIN_SERVER`

后台运行方式。

- `simple`：单进程 Flask 服务，内存占用低，适合个人使用。
- `gunicorn`：使用 gunicorn，适合多人使用或更高并发。

`GUNICORN_WORKERS`

`ADMIN_SERVER=gunicorn` 时生效，表示 worker 数量。

`GUNICORN_THREADS`

`ADMIN_SERVER=gunicorn` 时生效，表示每个 worker 的线程数。

`GUNICORN_TIMEOUT`

`ADMIN_SERVER=gunicorn` 时生效，请求超时时间，单位秒。

`MALLOC_ARENA_MAX`

限制内存分配 arena 数量，用于降低 Python 进程静默内存占用。默认 `2`。

`PYTHONOPTIMIZE`

Python 优化等级。默认 `2`，会去掉 assert 和部分调试信息。

`PYTHONDONTWRITEBYTECODE`

是否禁止写 `.pyc` 文件。默认 `1`，减少运行态文件。

### Docker 容器命名与网络

`WIREGUARD_CONTAINER_NAME`

WireGuard 容器名称。默认 `wireguard`。

`ADMIN_CONTAINER_NAME`

后台容器名称。默认 `vpn-admin`。

`ADMIN_NETWORK_MODE`

后台容器网络模式。默认 `host`。

- `host`：容器直接使用宿主机网络，访问 `127.0.0.1` 就是访问宿主机。
- `bridge`：桥接网络，需要自行调整数据库地址和端口映射。

### WireGuard 配置

`PUID`

WireGuard 容器内文件所属用户 ID。通常填写服务器普通用户的 UID。

`PGID`

WireGuard 容器内文件所属用户组 ID。通常填写服务器普通用户的 GID。

`TZ`

容器时区。中国大陆常用 `Asia/Shanghai`。

`SERVERURL`

WireGuard 对外访问地址，填写服务器公网 IP 或域名。

`SERVERPORT`

WireGuard 对外 UDP 端口。compose 会映射为：

```text
SERVERPORT:51820/udp
```

`PEERS`

WireGuard 客户端数量。后台页面也可以修改此值。

`PEERDNS`

客户端 DNS。可以使用公共 DNS，例如 `1.1.1.1`、`8.8.8.8`，也可以使用你的内网 DNS。

`INTERNAL_SUBNET`

WireGuard 内部网段。已有配置生成后不建议随意修改，否则可能影响已有客户端。

## 第四步：启动服务

执行：

```bash
docker compose up -d --build
```

查看后台日志：

```bash
docker logs vpn-admin
```

首次启动会自动建表，并创建初始管理员。日志中会打印初始订阅 token。

## 第五步：访问后台

默认后台地址：

```text
http://服务器IP:19090/sub/clash
```

如果你修改了 `PORT` 或 `URL_PREFIX`，请按实际配置访问。

## 第六步：使用后台

### 登录

使用 `.env` 中的：

```text
ADMIN_USERNAME
ADMIN_PASSWORD
```

登录后台。

### 切换 WireGuard 配置

在“切换入口配置”中可以修改：

- 公网地址
- 外网端口
- PEERS

点击“应用并重启容器”后，任务会异步执行。页面会立即提示提交成功，请等待约 10 秒后刷新页面或重试订阅。

后台会执行：

- 更新 `.env`
- 更新 peer 配置中的 Endpoint
- 重建 WireGuard 容器
- 执行 `run.sh`
- 生成新的 Clash 配置
- 写入操作日志

### 刷新配置

点击“刷新配置”会执行：

```bash
./run.sh
```

用于重新生成 `clash-config.yaml`。

### 用户和订阅

每个用户都有独立 token。账号列表中可以一键复制订阅链接。

重置 token 后：

- 新 token 立即生效
- 旧 token 立即失效
- Redis 中旧 token 缓存会被清理

订阅链接格式：

```text
https://你的域名/sub/clash/file/clash.yaml?token=用户token
```

如果未配置反向代理，也可以直接访问：

```text
http://服务器IP:19090/sub/clash/file/clash.yaml?token=用户token
```

## OpenResty / Nginx 反向代理

推荐使用独立域名或路径前缀代理后台。

如果使用默认 `URL_PREFIX=/sub/clash`，OpenResty 可以代理：

```text
前端路径：/sub/clash
后端地址：http://172.17.0.1:19090
```

Nginx 示例：

```nginx
location ^~ /sub/clash {
    proxy_pass http://172.17.0.1:19090;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

如果 OpenResty 容器中 `172.17.0.1` 不通，可以进入容器查看默认网关：

```bash
docker exec -it openresty sh -c "ip route | awk '/default/ {print \$3}'"
```

然后把 `proxy_pass` 中的地址替换为查出来的网关地址。

## 安全建议

- 不要提交 `.env`
- 不要提交 `vpn-config/`
- 不要提交 `clash-config.yaml`
- 不要提交日志文件
- 不要把 PostgreSQL 和 Redis 对公网全开放
- 后台建议只对可信网络开放，或在 OpenResty / Nginx 前加 IP 白名单、HTTPS、Basic Auth
- `/var/run/docker.sock` 挂载给后台后，后台具备操作 Docker 的能力，请保护好后台登录账号

## 常见问题

### 修改 `ADMIN_PASSWORD` 后为什么登录密码没变？

`ADMIN_PASSWORD` 只在首次创建管理员时生效。管理员已存在后，修改 `.env` 不会自动覆盖数据库中的密码。

请登录后台，在账号管理中修改密码。

### `PEERS` 调小后，旧 peer 目录会删除吗？

不会删除旧目录。订阅生成脚本只读取前 N 个 peer，避免旧节点继续出现在 Clash 配置里。

### 端口切换后为什么要等一会儿？

端口切换是异步执行的。后台需要更新配置、重建 WireGuard 容器并执行 `run.sh`。通常等待约 10 秒后再刷新页面或重试订阅。

### 后台内存占用如何降低？

默认使用：

```text
ADMIN_SERVER=simple
```

这是低内存的单进程模式，适合个人使用。如果需要更高并发，可以改为：

```text
ADMIN_SERVER=gunicorn
```
