# WireGuard Clash 管理后台

这是一个轻量 Docker Web 后台，用于管理 `linuxserver/wireguard` 容器，并生成带 token 鉴权的 Clash 订阅文件。

主要功能：

- 登录后台
- 创建、禁用、启用用户
- 重置用户密码
- 重置订阅 token，旧 token 立即失效
- 一键复制每个用户的订阅链接
- 每 5 小时检测 GitHub 是否发布新版本
- 发现新版本后提示管理员确认更新
- 从源码仓库同步白名单文件到运行目录并重建后台容器
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
├── VERSION                # 当前运行版本号
├── .env.example           # 环境变量示例，复制为 .env 后使用
├── .gitignore             # 排除运行态和敏感文件
├── wg-clash-admin/        # 推荐保留的源码仓库目录，用于在线更新
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

注意：修改 `URL_PREFIX` 后需要重新创建 `vpn-admin` 容器才会生效：

```bash
docker compose up -d --force-recreate vpn-admin
```

`STARTUP_WAIT_SECONDS`

后台启动时等待 PostgreSQL 和 Redis 可连接的最长秒数。默认 `90`。

`ADMIN_SERVER`

后台运行方式。

- `simple`：单进程 Flask 服务，内存占用低，适合个人使用。
- `gunicorn`：使用 gunicorn，适合多人使用或更高并发。

`ADMIN_UPDATER_IMAGE`

自更新时临时 updater 容器使用的镜像。默认留空，后台会自动识别当前 `vpn-admin` 容器正在使用的镜像。

只有自动识别失败时才需要手动填写，例如：

```text
ADMIN_UPDATER_IMAGE=vpn-vpn-admin:latest
```

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

`EXTERNAL_SUBSCRIPTION_TIMEOUT`

拉取其他 vpn-admin 订阅源时的单个请求超时时间，单位秒。默认 `4`。外部订阅源失败、错误或超时都会被跳过，不影响本机订阅返回。

`EXTERNAL_SUBSCRIPTION_MAX_BYTES`

单个外部订阅源允许下载的最大字节数。默认 `1048576`，也就是 1MB，用于避免异常大文件拖垮服务。

### 订阅合并

后台支持把多台服务器的订阅合并成一个 Clash 订阅。进入后台的“订阅合并”，添加其他 vpn-admin 的 Clash 订阅链接即可。

工作方式：

- 客户端每次请求本机 `/file/clash.yaml?token=...` 时，后台先读取本机 `clash-config.yaml`。
- 然后依次请求已启用的外部订阅源。
- 请求成功且 YAML 格式正常时，会把外部节点、策略组和规则合并到本机订阅中。
- 请求失败、超时、HTTP 错误、YAML 异常或文件过大时，会跳过该订阅源，并记录操作日志。
- 任意外部订阅源异常都不会阻塞本机订阅返回。

建议每个外部订阅源使用清晰名称，例如 `hk-01`、`jp-01`。合并时会给外部节点和策略组自动加名称前缀，避免和本机节点重名。

### 版本检测与在线更新

`UPDATE_REPO_DIR`

源码仓库目录。推荐结构是在运行目录下保留一份 Git 克隆：

```text
/home/wzh/vpn/wg-clash-admin
```

容器内对应默认值：

```text
/app/vpn/wg-clash-admin
```

后台不会直接从这个目录运行服务。它只把这个目录当作“源码仓库”，用于检查版本、拉取新代码，并把白名单文件同步覆盖到运行目录。

`UPDATE_REPO_URL`

开源源码仓库地址。默认：

```text
https://github.com/jqmzfj/wg-clash-admin.git
```

如果 `UPDATE_REPO_DIR` 指向的目录不存在，后台检查版本时会尝试自动 clone 这个仓库。

`UPDATE_BRANCH`

用于检测和更新的 Git 分支。默认 `main`。如果你的 GitHub 仓库使用 `master` 或其他分支，请改成对应分支名。

`UPDATE_VERSION_FILE`

版本号文件名。默认 `VERSION`。运行目录和源码仓库里都应该有这个文件，文件内容只写版本号，例如：

```text
0.1.0
```

`UPDATE_CHECK_INTERVAL_SECONDS`

自动检测 GitHub 新版本的间隔，单位秒。默认 `18000`，也就是 5 小时。

`UPDATE_SYNC_COMPOSE`

是否在在线更新时同步覆盖运行目录中的 `docker-compose.yml`。默认：

```text
false
```

- `false`：安全模式，不自动覆盖服务器本机 compose 配置。
- `true`：同步 compose 模板，适合你确认新版本必须更新 compose 时使用。覆盖前会自动备份到 `deploy/backups/`。

如果你的服务器已经有自定义容器名、网络模式、端口、1Panel / OpenResty 相关配置，建议保持 `false`，需要更新 compose 时先对比后手动合并。

`UPDATE_SYNC_PATHS`

点击更新时，从源码仓库同步覆盖到运行目录的白名单路径。默认：

```text
admin,run.sh,generate_clash_yaml.py,README.md,.env.example,VERSION
```

不要把这些路径加入白名单：

- `.env`
- `vpn-config`
- `clash-config.yaml`
- `run.log`

这些都是运行数据或敏感配置，不应该被线上更新覆盖。

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

## 第四步：推荐部署结构

推荐把“运行目录”和“源码仓库目录”分开。以 `/home/wzh/vpn` 为例：

```text
/home/wzh/vpn
├── admin
├── docker-compose.yml
├── generate_clash_yaml.py
├── run.sh
├── VERSION
├── .env
├── wg-clash-admin
│   ├── admin
│   ├── docker-compose.yml
│   ├── generate_clash_yaml.py
│   ├── README.md
│   ├── run.sh
│   └── VERSION
├── vpn-config
├── clash-config.yaml
└── run.log
```

`/home/wzh/vpn` 是真正运行 Docker Compose 的目录。

`/home/wzh/vpn/wg-clash-admin` 是 GitHub 拉下来的源码仓库，在线更新时会先更新这里，再把 `UPDATE_SYNC_PATHS` 中配置的文件覆盖到运行目录。

## 第五步：快捷部署命令

```bash
mkdir -p /home/wzh/vpn
cd /home/wzh/vpn
git clone https://github.com/jqmzfj/wg-clash-admin.git wg-clash-admin
cp wg-clash-admin/.env.example .env
cp -a wg-clash-admin/admin ./admin
cp wg-clash-admin/docker-compose.yml ./docker-compose.yml
cp wg-clash-admin/generate_clash_yaml.py ./generate_clash_yaml.py
cp wg-clash-admin/run.sh ./run.sh
cp wg-clash-admin/VERSION ./VERSION
chmod +x ./run.sh
vim .env
docker compose up -d --build
```

如果你已经有运行目录，只需要确认源码仓库存在：

```bash
cd /home/wzh/vpn
git clone https://github.com/jqmzfj/wg-clash-admin.git wg-clash-admin
```

然后在 `.env` 中确认：

```text
UPDATE_REPO_DIR=/app/vpn/wg-clash-admin
UPDATE_REPO_URL=https://github.com/jqmzfj/wg-clash-admin.git
UPDATE_BRANCH=main
UPDATE_VERSION_FILE=VERSION
UPDATE_SYNC_COMPOSE=false
```

## 第六步：启动服务

执行：

```bash
docker compose up -d --build
```

查看后台日志：

```bash
docker logs vpn-admin
```

首次启动会自动建表，并创建初始管理员。日志中会打印初始订阅 token。

## 第七步：访问后台

默认后台地址：

```text
http://服务器IP:19090/sub/clash
```

如果你修改了 `PORT` 或 `URL_PREFIX`，请按实际配置访问。

## 第八步：使用后台

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

### 版本更新

后台会每 5 小时检查一次源码仓库对应 GitHub 分支中的 `VERSION` 文件。

如果 GitHub 上的版本号和运行目录的 `VERSION` 不一致，左上角会提示“发现新版本”。管理员确认更新后，后台会异步执行：

```bash
cd /app/vpn/wg-clash-admin
git pull --ff-only origin main
cp /app/vpn/wg-clash-admin/白名单路径 /app/vpn/对应路径
docker compose up -d --build vpn-admin
```

重建命令由临时容器 `vpn-admin-updater` 执行，避免 `vpn-admin` 在重建自己时把更新流程中断。执行日志会写入：

```text
deploy/update-rebuild.log
```

实际同步的路径由 `UPDATE_SYNC_PATHS` 控制。默认会同步：

- `admin`
- `run.sh`
- `generate_clash_yaml.py`
- `README.md`
- `.env.example`
- `VERSION`

`docker-compose.yml` 属于服务器本机部署配置，默认不会被在线更新覆盖，避免把容器名、网络模式、端口映射等运行配置冲掉。需要更新 compose 模板时，请先对比后手动合并。

如果你确认新版本必须同步 compose，可以在 `.env` 中临时设置：

```text
UPDATE_SYNC_COMPOSE=true
```

更新完成并确认正常后，建议再改回：

```text
UPDATE_SYNC_COMPOSE=false
```

更新前后台会把被覆盖的旧文件备份到：

```text
deploy/backups/update-时间戳/
```

使用前请确认：

- `UPDATE_REPO_DIR` 指向源码仓库目录，例如 `/app/vpn/wg-clash-admin`
- `UPDATE_REPO_URL` 是 `https://github.com/jqmzfj/wg-clash-admin.git`
- 源码仓库配置了 `origin` 远程仓库
- 本地没有会阻止快进更新的未提交改动
- `vpn-admin` 已挂载 `/var/run/docker.sock`
- 后台登录账号是 `admin` 角色

更新任务提交后页面会立即返回。请等待约 30 秒后刷新页面；如果更新失败，可以在“最近操作”里查看错误原因。

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

## 开源协议

本项目使用 MIT License 开源，允许个人和商业场景自由使用、修改和分发。详情见仓库中的 `LICENSE` 文件。

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
