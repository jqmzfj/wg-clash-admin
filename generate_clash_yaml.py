#!/usr/bin/env python3
import os
import re
import yaml

CONFIG_DIR = "./vpn-config"
OUTPUT_FILE = "./clash-config.yaml"
COMPOSE_FILE = "./docker-compose.yml"
ENV_FILE = "./.env"

proxies = []

def read_env_value(key, default=""):
    if os.environ.get(key):
        return os.environ[key]
    try:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return default

def peer_sort_key(peer_dir):
    match = re.fullmatch(r"peer(\d+)", peer_dir)
    return (0, int(match.group(1))) if match else (1, peer_dir)

def read_peer_limit():
    if os.environ.get("PEERS"):
        return int(os.environ["PEERS"])
    try:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line.startswith("PEERS="):
                    return int(line.split("=", 1)[1].strip().strip('"').strip("'"))
    except OSError:
        pass
    try:
        with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
            text = f.read()
        match = re.search(r"PEERS=(\d+)", text)
        if match:
            return int(match.group(1))
        match = re.search(r"PEERS=\$\{PEERS:-(\d+)\}", text)
        if match:
            return int(match.group(1))
    except OSError:
        pass
    return None

peer_limit = read_peer_limit()
local_node_prefix = read_env_value("LOCAL_NODE_PREFIX", "peer").strip() or "peer"

for peer_dir in sorted(os.listdir(CONFIG_DIR), key=peer_sort_key):
    peer_match = re.fullmatch(r"peer(\d+)", peer_dir)
    if peer_limit is not None and peer_match and int(peer_match.group(1)) > peer_limit:
        continue

    conf_file = os.path.join(CONFIG_DIR, peer_dir, f"{peer_dir}.conf")
    if not os.path.isfile(conf_file):
        continue

    with open(conf_file, "r") as f:
        lines = f.read().splitlines()

    private_key = public_key = preshared_key = endpoint = address = ""

    for line in lines:
        line = line.strip()
        if line.startswith("PrivateKey"):
            private_key = line.split("=",1)[1].strip()
        elif line.startswith("PublicKey"):
            public_key = line.split("=",1)[1].strip()
        elif line.startswith("PresharedKey"):
            preshared_key = line.split("=",1)[1].strip()
        elif line.startswith("Endpoint"):
            endpoint = line.split("=",1)[1].strip()
        elif line.startswith("Address"):
            address = line.split("=",1)[1].split("/")[0].strip()

    host, port = endpoint.split(":")

    node_index = peer_match.group(1) if peer_match else peer_dir
    proxies.append({
        "name": f"{local_node_prefix}{node_index}",
        "type": "wireguard",
        "server": host,
        "port": int(port),
        "ip": address,
        "private-key": private_key,
        "public-key": public_key,
        "pre-shared-key": preshared_key,
        "allowed-ips": ["0.0.0.0/0"],
        "mtu": 1200,
        "remote-dns-resolve": True,
        "dns": ["1.1.1.1", "8.8.8.8"],
        "udp": True
    })

yaml_data = {
    # ✅ 必须项
    "mixed-port": 7891,
    "allow-lan": True,
    "bind-address": "*",
    "mode": "rule",
    "log-level": "info",
    "ipv6": False,

    # ✅ DNS（关键）
    "dns": {
        "enable": True,
        "ipv6": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ]
    },

    "proxies": proxies,

    "proxy-groups": [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": [p["name"] for p in proxies] + ["DIRECT"]
        },
        {
            "name": "🎬 国际媒体",
            "type": "select",
            "proxies": ["🚀 节点选择"] + [p["name"] for p in proxies] + ["DIRECT"]
        },
        {
            "name": "📲 电报代理",
            "type": "select",
            "proxies": ["🚀 节点选择"] + [p["name"] for p in proxies] + ["DIRECT"]
        },
        {
            "name": "🍎 苹果服务",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择"] + [p["name"] for p in proxies]
        },
        {
            "name": "🛑 广告拦截",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"]
        }
    ],

    "rules": [
        "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT",
        "IP-CIDR,10.0.0.0/8,DIRECT",
        "IP-CIDR,172.16.0.0/12,DIRECT",
        "IP-CIDR,192.168.0.0/16,DIRECT",
        "IP-CIDR,100.64.0.0/10,DIRECT",
        "DOMAIN-KEYWORD,adservice,🛑 广告拦截",
        "DOMAIN-SUFFIX,doubleclick.net,🛑 广告拦截",
        "DOMAIN-SUFFIX,googleadservices.com,🛑 广告拦截",
        "DOMAIN-SUFFIX,mmstat.com,🛑 广告拦截",
        "DOMAIN-SUFFIX,apple.com,🍎 苹果服务",
        "DOMAIN-SUFFIX,icloud.com,🍎 苹果服务",
        "DOMAIN-SUFFIX,icloud-content.com,🍎 苹果服务",
        "DOMAIN-SUFFIX,mzstatic.com,🍎 苹果服务",
        "DOMAIN-KEYWORD,google,🚀 节点选择",
        "DOMAIN-KEYWORD,gmail,🚀 节点选择",
        "DOMAIN-SUFFIX,1e100.net,🚀 节点选择",
        "DOMAIN-SUFFIX,g.co,🚀 节点选择",
        "DOMAIN-SUFFIX,ggpht.com,🚀 节点选择",
        "DOMAIN-SUFFIX,googleapis.com,🚀 节点选择",
        "DOMAIN-SUFFIX,gstatic.com,🚀 节点选择",
        "DOMAIN-SUFFIX,gvt0.com,🚀 节点选择",
        "DOMAIN-SUFFIX,gvt1.com,🚀 节点选择",
        "DOMAIN-SUFFIX,gvt2.com,🚀 节点选择",
        "DOMAIN-SUFFIX,gvt3.com,🚀 节点选择",
        "DOMAIN-SUFFIX,youtu.be,🎬 国际媒体",
        "DOMAIN-SUFFIX,youtube.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,youtube-nocookie.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,googlevideo.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,ytimg.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,netflix.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,nflxvideo.net,🎬 国际媒体",
        "DOMAIN-SUFFIX,disneyplus.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,spotify.com,🎬 国际媒体",
        "DOMAIN-SUFFIX,twitch.tv,🎬 国际媒体",
        "DOMAIN-SUFFIX,t.me,📲 电报代理",
        "DOMAIN-SUFFIX,tdesktop.com,📲 电报代理",
        "DOMAIN-SUFFIX,telegra.ph,📲 电报代理",
        "DOMAIN-SUFFIX,telegram.me,📲 电报代理",
        "DOMAIN-SUFFIX,telegram.org,📲 电报代理",
        "IP-CIDR,91.108.4.0/22,📲 电报代理,no-resolve",
        "IP-CIDR,91.108.8.0/21,📲 电报代理,no-resolve",
        "IP-CIDR,91.108.16.0/22,📲 电报代理,no-resolve",
        "IP-CIDR,91.108.56.0/22,📲 电报代理,no-resolve",
        "IP-CIDR,149.154.160.0/20,📲 电报代理,no-resolve",
        "DOMAIN-SUFFIX,github.com,🚀 节点选择",
        "DOMAIN-SUFFIX,githubusercontent.com,🚀 节点选择",
        "DOMAIN-SUFFIX,openai.com,🚀 节点选择",
        "DOMAIN-SUFFIX,chatgpt.com,🚀 节点选择",
        "DOMAIN-SUFFIX,bing.com,🚀 节点选择",
        "DOMAIN-SUFFIX,cloudflare.com,🚀 节点选择",
        "DOMAIN-SUFFIX,cloudfront.net,🚀 节点选择",
        "DOMAIN-SUFFIX,amazonaws.com,🚀 节点选择",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-KEYWORD,-cn,DIRECT",
        "DOMAIN-KEYWORD,alicdn,DIRECT",
        "DOMAIN-KEYWORD,alipay,DIRECT",
        "DOMAIN-KEYWORD,baidu,DIRECT",
        "DOMAIN-KEYWORD,taobao,DIRECT",
        "DOMAIN-KEYWORD,tencent,DIRECT",
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,amap.com,DIRECT",
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,bilivideo.com,DIRECT",
        "DOMAIN-SUFFIX,douban.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,youku.com,DIRECT",
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "MATCH,🚀 节点选择"
    ]
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    yaml.safe_dump(yaml_data, f, allow_unicode=True, sort_keys=False)

print(f"✅ 完整 Clash 配置已生成: {OUTPUT_FILE}")
