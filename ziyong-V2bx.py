#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XBoard 节点部署脚本  v0.7
适用: Debian 12 / root 运行

用法 (方案乙, 不落盘):
  python3 <(curl -fsSL https://raw.githubusercontent.com/hahaaa789/ziyongSSH/main/ziyong-V2bx.py) \
      --panel https://your-panel.com --path xxxxxxxx --token xxx --apikey xxx --group 2

也可以先存本地:
  curl -fsSL -o /root/nodeup.py https://raw.githubusercontent.com/hahaaa789/ziyongSSH/main/ziyong-V2bx.py
  python3 /root/nodeup.py --panel ... --path ... --token ... --apikey ...

参数配好一次后会存到 /etc/V2bX/.node_setup_conf.json (600),
以后直接 python3 /root/nodeup.py 即可, 不用再带参数.

v0.7 相比 v0.6:
  1. 一键部署新增"同编号覆盖": 检测到面板已存在同编号的节点组时,
     列出清单 -> 二次确认(回车=取消, 必须输 y) -> 整组删除 -> 再建新的.
     跨主机名也能识别 (20010-A机 与 20010-B机 视为同一编号).
  2. 覆盖动作只在菜单 1 一键部署里出现; 菜单 2/3/4 新增、菜单 5 复制
     完全不含任何删除逻辑, 行为与 v0.6 一致.
  3. 新增菜单 14 新增分割线: 内容交互手填, 只在面板建一条占位, 不动本机.

v0.6 相比 v0.5:
  1. 节点命名规范定死: 编号-主机名-协议-备注
     协议段用"整段全等"识别 (不数 -, 不认裸 ss, 必须一字不落是 ss22)
     顺带修掉 v0.5 的 bug: 主机名以数字结尾(如 HK-01)会被误剥成 HK
  2. 新增改 SNI 功能: VLESS 改 Reality server_name, HY2 改证书域名
     面板 + 本机 config.json 同步改, 只改选中的单个节点
  3. 菜单 7 面板浏览去掉 60 条截断, 全量列出
  4. 菜单 6/7 的字母选项 (d/e/f) 全改成数字, 交互说明重写

v0.5 相比 v0.4:
  1. 一键部署/修复模式自动顺带配置转发环境 (hosts + iptables + ip_forward),
     全部幂等, 失败只警告不中断部署
  2. 新增菜单 17 转发环境检查/修复 (可单独手动跑, 带端口冲突展示)
  3. 新增菜单 18 修改本机主机名, 改完可选批量改面板节点名
  4. 菜单 14-16 预留空号

v0.4 相比 v0.3:
  1. 本机节点识别改为"强证据优先": config.json 的 NodeID + 节点名含主机名
     + 编号匹配 + 复制节点. IP 匹配降级为兜底(前面全空才用)并标 仅供参考.
     中转/落地机的出口 IP 会被别的机器节点借用, v0.3 直接采信导致误判.
  2. 编号推断平票时, 优先选后缀剥得更干净的那个标识
  3. 新机器进来直接进编号输入框, 不再多问一次 y
  4. V2bX 安装源改为自持镜像 V2BX_REPO / V2BX_VERSION, 防上游删库

v0.3 相比 v0.2:
  1. 顶部显示本机全部相关节点(含分割线/复制节点)并带端口
  2. 新机器进脚本直接问编号
  3. 敏感信息全部走参数/交互, 脚本正文零硬编码
  4. HY2 跳跃段冲突时给出提醒(不自动分配)
"""

import os, sys, re, json, time, random, secrets, subprocess, base64, socket

# ==================== 配置区 (v0.3 全部运行时注入) ====================
PANEL_URL   = ""
SECURE_PATH = ""
ADMIN_TOKEN = ""
V2BX_APIKEY = ""
GROUP_IDS   = ["2"]
REALITY_SNI = "apple.com"
CERT_DOMAIN = "www.bing.com"

# V2bX 安装源 (自持镜像, 防上游删库)
V2BX_REPO    = "hahaaa789"
V2BX_VERSION = "v0.4.0"

PORT_MIN, PORT_MAX = 20000, 50000
HOP_DEFAULT = (60000, 62999)
HOP_EXTRA   = (63000, 65535)

V2BX_DIR  = "/etc/V2bX"
V2BX_CONF = "/etc/V2bX/config.json"
SBOX_DIR  = "/etc/s-box"
CERT_FILE = "/etc/s-box/cert.pem"
KEY_FILE  = "/etc/s-box/private.key"
PUB_FILE  = "/etc/s-box/public.key"
NFT_DIR   = "/etc/nftables.d"
NFT_FILE  = "/etc/nftables.d/hy2-hop.nft"
NFT_CONF  = "/etc/nftables.conf"
STATE_FILE = "/etc/V2bX/.node_setup_state.json"
CONF_FILE  = "/etc/V2bX/.node_setup_conf.json"

API = ""

TYPE_CN = {"vless": "VLESS", "hysteria": "HY2", "shadowsocks": "SS22",
           "trojan": "Trojan", "vmess": "VMess"}
CORE_TYPE = {"vless": "vless", "hysteria": "hysteria2", "shadowsocks": "shadowsocks"}

# ==================== 通用输出 ====================
C_R="\033[31m"; C_G="\033[32m"; C_Y="\033[33m"; C_B="\033[36m"; C_0="\033[0m"

def ok(m):   print(C_G + "[OK] " + C_0 + m)
def warn(m): print(C_Y + "[!] " + C_0 + m)
def err(m):  print(C_R + "[X] " + C_0 + m)
def info(m): print(m)
def line():  print("-" * 60)

_STEP = {"i": 0, "n": 0, "t0": 0.0}

def step_total(n):
    _STEP["i"] = 0; _STEP["n"] = n

def step(title):
    _STEP["i"] += 1
    _STEP["t0"] = time.time()
    print("")
    print(C_B + "[%d/%d] %s" % (_STEP["i"], _STEP["n"], title) + C_0)

def step_done():
    print("耗时 %.1fs" % (time.time() - _STEP["t0"]))

def die(msg, built=None):
    print("")
    err(msg)
    if built:
        print("")
        warn("以下节点已经建好, 脚本不会自动删除, 请自行到面板确认:")
        for b in built:
            info("id=%s  name=%s" % (b.get("id"), b.get("name")))
    print("")
    sys.exit(1)

# v0.3: 管道/进程替换下 stdin 可能不是终端, 交互全部强制走 /dev/tty
_TTY = None

def _tty():
    """返回可用的终端输入句柄. python3 <(curl ...) 模式下 stdin 仍是终端,
    但 curl | python3 模式下不是, 这里统一兜底"""
    global _TTY
    if _TTY is not None:
        return _TTY
    if sys.stdin and sys.stdin.isatty():
        _TTY = sys.stdin
    else:
        try:
            _TTY = open("/dev/tty", "r")
        except Exception:
            _TTY = sys.stdin
    return _TTY

def _input(prompt=""):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    s = _tty().readline()
    if not s:
        raise EOFError("输入已结束")
    return s.rstrip("\n").rstrip("\r")

def pause():
    _input("回车继续 ...")

def ask(prompt, default=""):
    if default != "":
        s = _input("%s [回车=%s]: " % (prompt, default)).strip()
        return s if s else default
    return _input("%s: " % prompt).strip()

def ask_secret(prompt):
    """输入敏感串, 不回显"""
    try:
        import getpass
        return getpass.getpass("%s: " % prompt).strip()
    except Exception:
        return _input("%s: " % prompt).strip()

def confirm(prompt, default=True):
    """回车即默认. default=True 时回车就是确认, 只有输入 n 才取消"""
    tail = "[回车=确认, n=取消]" if default else "[回车=取消, y=确认]"
    s = _input("%s %s: " % (prompt, tail)).strip().lower()
    if not s:
        return default
    if s in ("y", "yes"):
        return True
    if s in ("n", "no"):
        return False
    return default

def ask_int(prompt, default=None, lo=None, hi=None):
    while True:
        d = "" if default is None else str(default)
        s = ask(prompt, d)
        if not s:
            return default
        if not s.lstrip("-").isdigit():
            err("请输入数字")
            continue
        v = int(s)
        if lo is not None and v < lo:
            err("不能小于 %d" % lo); continue
        if hi is not None and v > hi:
            err("不能大于 %d" % hi); continue
        return v

def run(cmd, check=True, timeout=300):
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout)
    out = p.stdout.decode("utf-8", "ignore")
    if check and p.returncode != 0:
        raise RuntimeError("命令失败: %s\n%s" % (cmd, out))
    return p.returncode, out

# ==================== v0.3 新增: 参数解析 + 面板连接配置 ====================
def parse_args(argv):
    """支持 --key value 和 --key=value 两种写法"""
    out = {}
    i = 0
    keys = ("panel", "path", "token", "apikey", "group",
            "sni", "cert-domain", "reconfig", "help")
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            out["help"] = "1"; i += 1; continue
        if not a.startswith("--"):
            i += 1; continue
        body = a[2:]
        if "=" in body:
            k, _, v = body.partition("=")
        else:
            k = body
            v = ""
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                v = argv[i + 1]; i += 1
            else:
                v = "1"
        k = k.strip().lower()
        if k in keys:
            out[k] = v.strip()
        i += 1
    return out

def print_usage():
    print("")
    print("XBoard 节点部署脚本 v0.7")
    print("")
    print("用法:")
    print("  python3 <(curl -fsSL <脚本地址>) --panel <面板> --path <安全路径> \\")
    print("      --token <管理token> --apikey <V2bX APIKey> [--group 2]")
    print("")
    print("参数:")
    print("  --panel        面板地址, 例 https://panel.example.com")
    print("  --path         后台安全路径 secure_path")
    print("  --token        管理员 API token (带不带 "+chr(66)+"earer 前缀都行)")
    print("  --apikey       V2bX 对接用 APIKey")
    print("  --group        节点分组 id, 逗号分隔, 默认 2")
    print("  --sni          Reality SNI, 默认 apple.com")
    print("  --cert-domain  自签证书域名, 默认 www.bing.com")
    print("  --reconfig     忽略本地已存配置, 重新引导输入")
    print("")
    print("首次带参运行后会存到 %s (权限600)," % CONF_FILE)
    print("以后直接运行不带参数即可.")
    print("")

def load_conf():
    if not os.path.exists(CONF_FILE):
        return {}
    try:
        with open(CONF_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_conf(d):
    try:
        os.makedirs(V2BX_DIR, exist_ok=True)
        with open(CONF_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
        os.chmod(CONF_FILE, 0o600)
        ok("面板连接配置已保存 " + CONF_FILE + " (权限600)")
    except Exception as e:
        warn("配置保存失败: %s" % e)

def mask(s, keep=4):
    s = str(s or "")
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]

def norm_panel(u):
    u = (u or "").strip().rstrip("/")
    if u and not u.startswith("http"):
        u = "https://" + u
    return u

def wizard(cur):
    """缺参数时的交互引导"""
    print("")
    line()
    info("面板连接配置")
    line()
    info("这些信息只存在本机 %s, 不会写进脚本" % CONF_FILE)
    print("")
    p = ask("面板地址 (例 https://panel.example.com)", cur.get("panel", ""))
    p = norm_panel(p)
    if not p:
        die("面板地址不能为空")
    sp = ask("后台安全路径 secure_path", cur.get("path", ""))
    if not sp:
        die("安全路径不能为空")
    t = cur.get("token", "")
    if t:
        info("当前 token: " + mask(t))
        if confirm("沿用当前 token", True):
            pass
        else:
            t = ""
    if not t:
        t = ask_secret("管理员 API token (输入不回显)")
    if not t:
        die("token 不能为空")
    if t.lower().startswith("bearer "):
        t = t[7:].strip()
    k = cur.get("apikey", "")
    if k:
        info("当前 APIKey: " + mask(k))
        if not confirm("沿用当前 APIKey", True):
            k = ""
    if not k:
        k = ask_secret("V2bX APIKey (输入不回显)")
    if not k:
        die("APIKey 不能为空")
    g = ask("节点分组 id (逗号分隔)", ",".join(cur.get("group_ids") or ["2"]))
    gids = [x.strip() for x in g.split(",") if x.strip()] or ["2"]
    sni = ask("Reality SNI", cur.get("sni") or "apple.com")
    cd = ask("自签证书域名", cur.get("cert_domain") or "www.bing.com")
    return {"panel": p, "path": sp, "token": t, "apikey": k,
            "group_ids": gids, "sni": sni, "cert_domain": cd}

def setup_config(argv):
    """参数 > 本地配置 > 交互引导. 全部就绪后写入全局"""
    global PANEL_URL, SECURE_PATH, ADMIN_TOKEN, V2BX_APIKEY
    global GROUP_IDS, REALITY_SNI, CERT_DOMAIN, API
    a = parse_args(argv)
    if a.get("help"):
        print_usage(); sys.exit(0)
    cur = {} if a.get("reconfig") else load_conf()
    if a.get("panel"):  cur["panel"]  = norm_panel(a["panel"])
    if a.get("path"):   cur["path"]   = a["path"]
    if a.get("token"):
        t = a["token"]
        cur["token"] = t[7:].strip() if t.lower().startswith("bearer ") else t
    if a.get("apikey"): cur["apikey"] = a["apikey"]
    if a.get("group"):
        cur["group_ids"] = [x.strip() for x in a["group"].split(",") if x.strip()]
    if a.get("sni"):         cur["sni"] = a["sni"]
    if a.get("cert-domain"): cur["cert_domain"] = a["cert-domain"]
    need = [k for k in ("panel", "path", "token", "apikey") if not cur.get(k)]
    changed = bool(a) and not a.get("help")
    if need or a.get("reconfig"):
        if need and not a.get("reconfig"):
            print("")
            warn("缺少参数: " + ", ".join("--" + x for x in need))
            info("下面引导你逐项输入, 也可以 Ctrl+C 退出后用参数运行")
            info("参数用法看 --help")
        cur = wizard(cur)
        changed = True
    PANEL_URL   = cur["panel"]
    SECURE_PATH = cur["path"]
    ADMIN_TOKEN = cur["token"]
    V2BX_APIKEY = cur["apikey"]
    GROUP_IDS   = cur.get("group_ids") or ["2"]
    REALITY_SNI = cur.get("sni") or "apple.com"
    CERT_DOMAIN = cur.get("cert_domain") or "www.bing.com"
    API = PANEL_URL.rstrip("/") + "/api/v2/" + SECURE_PATH
    if changed:
        save_conf({"panel": PANEL_URL, "path": SECURE_PATH,
                   "token": ADMIN_TOKEN, "apikey": V2BX_APIKEY,
                   "group_ids": GROUP_IDS, "sni": REALITY_SNI,
                   "cert_domain": CERT_DOMAIN})
    return cur

def test_panel():
    """启动时验证面板连通 + token 有效"""
    print("")
    info("正在验证面板连接 ...")
    try:
        nodes = get_nodes()
    except Exception as e:
        print("")
        err("面板连接失败: %s" % e)
        info("面板   : %s" % PANEL_URL)
        info("路径   : %s" % SECURE_PATH)
        info("token  : %s" % mask(ADMIN_TOKEN))
        print("")
        info("排查方向: 域名解析 / 安全路径写错 / token 过期")
        info("重新配置请加 --reconfig 参数运行")
        print("")
        if confirm("现在重新输入面板配置", True):
            return False
        sys.exit(1)
    ok("面板连接正常, 共读到 %d 个节点" % len(nodes))
    return True

# ==================== 纯 Python X25519 (不依赖 cryptography) ====================
_P = 2**255 - 19
_A24 = 121665

def _cswap(swap, a, b):
    dummy = swap * ((a - b) % _P)
    return (a - dummy) % _P, (b + dummy) % _P

def _x25519(k_bytes, u_int):
    k = bytearray(k_bytes)
    k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(bytes(k), "little")
    x1 = u_int
    x2, z2, x3, z3 = 1, 0, u_int, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        a  = (x2 + z2) % _P
        aa = a * a % _P
        b  = (x2 - z2) % _P
        bb = b * b % _P
        e  = (aa - bb) % _P
        c  = (x3 + z3) % _P
        d  = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = x1 * pow((da - cb) % _P, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * ((aa + _A24 * e) % _P) % _P
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")

def _b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def gen_reality_keypair():
    """返回 (私钥, 公钥) 均为 base64url 无填充"""
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248; priv[31] &= 127; priv[31] |= 64
    priv = bytes(priv)
    pub = _x25519(priv, 9)
    return _b64url(priv), _b64url(pub)

def gen_ss2022_password(n=32):
    return base64.b64encode(secrets.token_bytes(n)).decode()

def gen_short_id():
    return secrets.token_hex(8)

# ==================== 面板 API (走系统 curl) ====================
def api(path, payload=None, method=None):
    url = API + path
    m = method or ("POST" if payload is not None else "GET")
    cmd = ["curl", "-s", "-S", "--max-time", "30",
           "-w", "\\n__HTTP__%{http_code}",
           "-X", m, url,
           "-H", "Authorization: Bearer " + ADMIN_TOKEN,
           "-H", "Content-Type: application/json",
           "-H", "Accept: application/json"]
    if payload is not None:
        cmd += ["-d", json.dumps(payload, ensure_ascii=False)]
    p = subprocess.run(cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=60)
    out = p.stdout.decode("utf-8", "ignore")
    errout = p.stderr.decode("utf-8", "ignore").strip()
    if p.returncode != 0:
        raise RuntimeError("curl 失败(%d): %s" % (p.returncode, errout[:300]))
    code = ""
    if "__HTTP__" in out:
        out, _, code = out.rpartition("__HTTP__")
        code = code.strip()
    out = out.strip()
    if code and not code.startswith("2"):
        raise RuntimeError("API HTTP %s: %s" % (code, out[:400]))
    try:
        return json.loads(out)
    except Exception:
        raise RuntimeError("API 返回非 JSON: " + out[:400])

def get_nodes():
    r = api("/server/manage/getNodes")
    return r.get("data") or []

def save_node(payload):
    r = api("/server/manage/save", payload)
    if not r.get("data"):
        raise RuntimeError("建节点失败: " + json.dumps(r, ensure_ascii=False)[:400])
    return r

def drop_node(node_id):
    """drop 接口对不存在的 id 也回 success, 所以必须回查确认"""
    api("/server/manage/drop", {"id": int(node_id)})
    time.sleep(0.6)
    still = [n for n in get_nodes() if int(n.get("id", -1)) == int(node_id)]
    if still:
        raise RuntimeError("节点 id=%s 删除后仍然存在" % node_id)
    return True

def find_node_by_name(nodes, name):
    return [n for n in nodes if n.get("name") == name]

def node_by_id(nodes, nid):
    for n in nodes:
        if int(n.get("id", -1)) == int(nid):
            return n
    return None

# ==================== 本机 IP 探测 ====================
def _curl_ip(url, family):
    rc, out = run("curl -%s -s --max-time 6 %s" % (family, url), check=False, timeout=15)
    out = out.strip()
    if rc == 0 and out and len(out) < 60 and " " not in out:
        return out
    return ""

def detect_ipv4():
    for u in ["https://api.ipify.org", "https://ifconfig.me", "https://4.ipw.cn"]:
        ip = _curl_ip(u, "4")
        if ip and ip.count(".") == 3:
            return ip
    return ""

def detect_ipv6():
    for u in ["https://api6.ipify.org", "https://ifconfig.me", "https://6.ipw.cn"]:
        ip = _curl_ip(u, "6")
        if ip and ":" in ip:
            return ip
    return ""

def choose_ip(ctx=None):
    print("")
    print("正在探测本机公网 IP ...")
    v4 = detect_ipv4()
    v6 = detect_ipv6()
    if v4: ok("IPv4: " + v4)
    else:  warn("IPv4: 未探测到")
    if v6: ok("IPv6: " + v6)
    else:  warn("IPv6: 未探测到")
    if not v4 and not v6:
        die("IPv4/IPv6 都探测不到, 请检查网络后重试")
    known = ""
    if ctx:
        for m in ctx.get("matched", []):
            if m.get("host") and m.get("host") != "127.0.0.1":
                known = m["host"]; break
    if known:
        print("")
        info("面板上本机已有节点使用的地址: " + C_G + known + C_0)
        if confirm("沿用这个地址", True):
            return known
    print("")
    print("1) IPv4" + ("  " + v4 if v4 else "  [不可用]"))
    print("2) IPv6" + ("  " + v6 if v6 else "  [不可用]"))
    print("3) 手动输入")
    dft = "1" if v4 else "2"
    s = ask("选择", dft)
    if s == "1":
        if not v4: die("IPv4 不可用")
        return v4
    if s == "2":
        if not v6: die("IPv6 不可用")
        return v6
    m = ask("请输入要写入面板的地址")
    if not m: die("地址不能为空")
    return m

# ==================== 证书 ====================
def ensure_cert():
    os.makedirs(SBOX_DIR, exist_ok=True)
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ok("证书已存在, 沿用 " + CERT_FILE)
        return
    cmd = ("openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) "
           "-keyout %s -out %s -subj \"/CN=%s\" -days 36500"
           % (KEY_FILE, CERT_FILE, CERT_DOMAIN))
    rc, out = run("bash -c '%s'" % cmd.replace("'", "'\\''"), check=False, timeout=60)
    if rc != 0 or not os.path.exists(CERT_FILE):
        rc, out = run("openssl req -x509 -nodes -newkey rsa:2048 -keyout %s -out %s "
                      "-subj '/CN=%s' -days 36500" % (KEY_FILE, CERT_FILE, CERT_DOMAIN),
                      check=False, timeout=120)
    if rc != 0 or not os.path.exists(CERT_FILE):
        die("自签证书生成失败:\n" + out)
    os.chmod(KEY_FILE, 0o600)
    ok("自签证书已生成 (CN=%s)" % CERT_DOMAIN)

# ==================== V2bX 安装 / 配置 ====================
def v2bx_installed():
    return os.path.exists("/usr/local/V2bX/V2bX") or os.path.exists("/usr/bin/V2bX")

def v2bx_running():
    rc, out = run("systemctl is-active V2bX", check=False, timeout=15)
    return out.strip() == "active"

def ensure_nftables():
    """v0.1 的坑: Debian 12 最小安装没有 nft, 端口跳跃静默失效"""
    rc, out = run("which nft", check=False, timeout=15)
    if rc == 0:
        return True
    info("正在安装 nftables (HY2 端口跳跃必须) ...")
    run("DEBIAN_FRONTEND=noninteractive apt-get update -qq", check=False, timeout=300)
    run("DEBIAN_FRONTEND=noninteractive apt-get install -y nftables",
        check=False, timeout=300)
    rc, out = run("which nft", check=False, timeout=15)
    if rc != 0:
        return False
    ok("nftables 已安装")
    return True

def install_v2bx():
    if v2bx_installed():
        ok("V2bX 已安装, 跳过")
        return
    info("正在下载并安装 V2bX, 这一步可能需要 1-3 分钟 ...")
    info("安装源: github.com/%s/V2bX-script  版本: %s"
         % (V2BX_REPO, V2BX_VERSION or "latest"))
    rc, out = run("cd /root && wget -N --no-check-certificate "
                  "https://raw.githubusercontent.com/%s/V2bX-script/master/install.sh "
                  "&& echo n | bash install.sh %s" % (V2BX_REPO, V2BX_VERSION),
                  check=False, timeout=600)
    if not v2bx_installed():
        die("V2bX 安装失败:\n" + out[-1500:])
    ok("V2bX 安装完成")

def backup_file(path):
    if os.path.exists(path):
        bak = "%s.bak.%d" % (path, int(time.time()))
        run("cp -a %s %s" % (path, bak))
        info("已备份 -> " + bak)
    return None

def load_v2bx_conf():
    if not os.path.exists(V2BX_CONF):
        return None
    try:
        with open(V2BX_CONF, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        warn("config.json 解析失败: %s" % e)
        return None

def base_conf():
    return {
        "Log": {"Level": "info", "Output": ""},
        "Cores": [{
            "Type": "sing",
            "Log": {"Level": "info", "Timestamp": True},
            "NTP": {"Enable": False, "Server": "time.apple.com", "ServerPort": 0},
            "OriginalPath": "/etc/V2bX/sing_origin.json"
        }],
        "Nodes": []
    }

def node_entry(node_id, node_type):
    """node_type: vless / hysteria2 / shadowsocks"""
    e = {
        "Core": "sing",
        "ApiHost": PANEL_URL,
        "ApiKey": V2BX_APIKEY,
        "NodeID": int(node_id),
        "NodeType": node_type,
        "Timeout": 30,
        "ListenIP": "::",
        "SendIP": "::"
    }
    if node_type == "vless":
        e["CertConfig"] = {"CertMode": "reality", "RejectUnknownSni": False,
                           "CertDomain": REALITY_SNI}
    elif node_type == "hysteria2":
        e["CertConfig"] = {"CertMode": "file", "RejectUnknownSni": False,
                           "CertDomain": CERT_DOMAIN,
                           "CertFile": CERT_FILE, "KeyFile": KEY_FILE}
    return e

def write_v2bx_conf(entries, replace_all):
    """replace_all=True 用新的 Nodes 完全替换; False 则追加"""
    os.makedirs(V2BX_DIR, exist_ok=True)
    conf = load_v2bx_conf()
    if conf is None or "Cores" not in conf:
        conf = base_conf()
    else:
        backup_file(V2BX_CONF)
    if replace_all:
        conf["Nodes"] = entries
    else:
        exist = conf.get("Nodes") or []
        have = set()
        for n in exist:
            have.add((n.get("NodeID"), n.get("NodeType")))
        for e in entries:
            if (e["NodeID"], e["NodeType"]) not in have:
                exist.append(e)
        conf["Nodes"] = exist
    with open(V2BX_CONF, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2, ensure_ascii=False)
    ok("已写入 " + V2BX_CONF + "  (共 %d 个节点)" % len(conf["Nodes"]))

def remove_from_conf(node_id):
    """从 config.json 摘掉一个 NodeID, 返回是否有改动"""
    conf = load_v2bx_conf()
    if not conf or not conf.get("Nodes"):
        return False
    before = len(conf["Nodes"])
    conf["Nodes"] = [n for n in conf["Nodes"]
                     if int(n.get("NodeID", -1)) != int(node_id)]
    if len(conf["Nodes"]) == before:
        return False
    backup_file(V2BX_CONF)
    with open(V2BX_CONF, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2, ensure_ascii=False)
    ok("已从 config.json 移除 NodeID=%s (剩 %d 个)" % (node_id, len(conf["Nodes"])))
    return True

def ensure_sing_origin():
    """文件存在就不动, 保护用户自定义分流配置"""
    p = os.path.join(V2BX_DIR, "sing_origin.json")
    if os.path.exists(p):
        return
    d = {"log": {"level": "info", "timestamp": True},
         "dns": {"servers": [{"tag": "default", "address": "local"}]},
         "inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}]}
    with open(p, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)
    info("已创建默认 sing_origin.json")

# ==================== nftables 端口跳跃 ====================
def _nft_rule_block(tag, family, rules):
    b = []
    b.append("table %s hy2hop%s {" % (family, tag))
    b.append("  chain prerouting {")
    b.append("    type nat hook prerouting priority dstnat; policy accept;")
    for hs, he, tp in rules:
        b.append("    udp dport %d-%d redirect to :%d" % (hs, he, tp))
    b.append("  }")
    b.append("}")
    return b

def load_hop_rules():
    """从 state 里读已有的跳跃规则 [(start,end,port), ...]"""
    st = load_state()
    out = []
    for r in st.get("hops", []):
        try:
            out.append((int(r[0]), int(r[1]), int(r[2])))
        except Exception:
            pass
    return out

def save_hop_rules(rules):
    st = load_state()
    st["hops"] = [[a, b, c] for a, b, c in rules]
    save_state(st)

def write_nft_hop(rules, hard=True):
    """rules: [(hop_start, hop_end, target_port), ...] 全量重写
    hard=True 时加载失败直接报错停止"""
    if not ensure_nftables():
        if hard:
            die("nftables 安装失败, HY2 端口跳跃无法生效.\n"
                "手动执行: apt-get install -y nftables  然后重跑本脚本")
        warn("nftables 不可用, 跳过端口跳跃")
        return False
    os.makedirs(NFT_DIR, exist_ok=True)
    body = ["# HY2 port hopping - generated by node_setup.py"]
    body += _nft_rule_block("", "ip", rules)
    body += _nft_rule_block("6", "ip6", rules)
    with open(NFT_FILE, "w") as f:
        f.write("\n".join(body) + "\n")
    ok("已写入 " + NFT_FILE)
    inc = 'include "/etc/nftables.d/*.nft"'
    cur = ""
    if os.path.exists(NFT_CONF):
        cur = open(NFT_CONF).read()
    if "nftables.d" not in cur:
        backup_file(NFT_CONF)
        with open(NFT_CONF, "a") as f:
            f.write("\n" + inc + "\n")
        info("已在 /etc/nftables.conf 追加 include")
    run("systemctl enable nftables >/dev/null 2>&1", check=False, timeout=30)
    run("nft delete table ip hy2hop >/dev/null 2>&1", check=False, timeout=15)
    run("nft delete table ip6 hy2hop6 >/dev/null 2>&1", check=False, timeout=15)
    rc, out = run("nft -f " + NFT_FILE, check=False, timeout=30)
    if rc != 0:
        if hard:
            die("nft 加载失败, HY2 跳跃不会生效:\n" + out.strip()[:300])
        warn("nft 加载失败: " + out.strip()[:200])
        return False
    save_hop_rules(rules)
    for hs, he, tp in rules:
        ok("跳跃已生效 %d-%d -> %d" % (hs, he, tp))
    return True

def add_hop_rule(hop_start, hop_end, target_port):
    """追加一条跳跃规则并重新加载全部"""
    rules = [r for r in load_hop_rules() if r[2] != target_port]
    rules.append((hop_start, hop_end, target_port))
    return write_nft_hop(rules, hard=False)

def del_hop_rule(target_port):
    rules = [r for r in load_hop_rules() if r[2] != int(target_port)]
    if not rules:
        run("nft delete table ip hy2hop >/dev/null 2>&1", check=False, timeout=15)
        run("nft delete table ip6 hy2hop6 >/dev/null 2>&1", check=False, timeout=15)
        if os.path.exists(NFT_FILE):
            os.remove(NFT_FILE)
        save_hop_rules([])
        info("已清空端口跳跃规则")
        return True
    return write_nft_hop(rules, hard=False)

def hop_overlap(hs, he):
    """v0.3 新增: 检查跳跃段是否与已有规则重叠, 返回冲突列表"""
    out = []
    for a, b, p in load_hop_rules():
        if hs <= b and a <= he:
            out.append((a, b, p))
    return out

def hop_overlap_list(rules, hs, he):
    """在给定规则集里查重叠 (hop_overlap 查的是 state 里的全部规则)"""
    return [(a, b, p) for a, b, p in rules if hs <= b and a <= he]

# ==================== 转发环境 (v0.5) ====================
def _hosts_has(hn):
    """/etc/hosts 里是否已有 127.0.1.1 指向本主机名"""
    try:
        with open("/etc/hosts", "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception:
        return False, ""
    for ln in txt.split("\n"):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if parts and parts[0] == "127.0.1.1" and hn in parts[1:]:
            return True, txt
    return False, txt

def fix_hosts(hn=None, verbose=True):
    """幂等: 给 /etc/hosts 补 127.0.1.1 主机名, 修 sudo 解析报错"""
    hn = hn or socket.gethostname()
    want = "127.0.1.1 " + hn
    hit, txt = _hosts_has(hn)
    if hit:
        if verbose:
            info("  hosts      已有 %s, 跳过" % want)
        return True
    try:
        with open("/etc/hosts", "a", encoding="utf-8") as f:
            if txt and not txt.endswith("\n"):
                f.write("\n")
            f.write(want + "\n")
        ok("  hosts      已添加 %s" % want)
        return True
    except Exception as e:
        warn("  hosts      写入失败: %s" % e)
        return False

def ensure_iptables(verbose=True):
    """幂等: 已装直接跳过, 不进 apt 流程"""
    rc, _ = run("command -v iptables >/dev/null 2>&1", check=False, timeout=15)
    if rc == 0:
        rc2, ver = run("iptables -V 2>/dev/null", check=False, timeout=15)
        if verbose:
            v = (ver or "").strip().split("\n")[0] or "未知版本"
            info("  iptables   已安装 (%s)" % v)
        return True
    info("  iptables   未安装, 正在安装 ...")
    rc3, _ = run("command -v apt-get >/dev/null 2>&1", check=False, timeout=15)
    if rc3 == 0:
        run("apt-get update", check=False, timeout=300)
        rc4, _ = run("DEBIAN_FRONTEND=noninteractive apt-get install -y iptables",
                     check=False, timeout=600)
    else:
        rc5, _ = run("command -v yum >/dev/null 2>&1", check=False, timeout=15)
        if rc5 == 0:
            rc4, _ = run("yum install -y iptables-services", check=False, timeout=600)
        else:
            rc4 = 1
            warn("  iptables   没有 apt-get 也没有 yum, 装不了")
    if rc4 == 0:
        ok("  iptables   安装完成")
        return True
    warn("  iptables   安装失败, 转发可能用不了")
    return False

def ensure_ip_forward(verbose=True):
    """持久化 + 立即生效. 容器里可能只读, 失败只警告"""
    run("sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf", check=False, timeout=30)
    run("echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf", check=False, timeout=30)
    # -w 精准生效, 不被 sysctl.conf 里其他坏行拖累
    run("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1", check=False, timeout=30)
    # -p best effort
    run("sysctl -p >/dev/null 2>&1", check=False, timeout=60)
    rc, cur = run("sysctl -n net.ipv4.ip_forward 2>/dev/null", check=False, timeout=30)
    cur = (cur or "").strip()
    if cur == "1":
        ok("  ip_forward 1 (已持久化)")
        return True
    warn("  ip_forward %s, 设置未生效" % (cur or "读取失败"))
    warn("             容器(LXC/OpenVZ)里这个参数可能是只读的, 转发用不了")
    warn("             节点部署不受影响, 继续")
    return False

def ensure_forward(verbose=True):
    """一键部署/修复模式顺带跑. 全程 check=False, 绝不中断主流程"""
    if verbose:
        info("配置转发环境 (hosts / iptables / ip_forward)")
    r1 = r2 = r3 = False
    try:
        r1 = fix_hosts(verbose=verbose)
    except Exception as e:
        warn("  hosts      异常: %s" % e)
    try:
        r2 = ensure_iptables(verbose=verbose)
    except Exception as e:
        warn("  iptables   异常: %s" % e)
    try:
        r3 = ensure_ip_forward(verbose=verbose)
    except Exception as e:
        warn("  ip_forward 异常: %s" % e)
    return r1 and r2 and r3

def dnat_rules():
    """读 iptables nat 表 PREROUTING, 返回 [(proto, dport, target), ...]"""
    out = []
    rc, txt = run("iptables -t nat -S PREROUTING 2>/dev/null", check=False, timeout=20)
    if rc != 0 or not txt:
        return out
    for ln in txt.split("\n"):
        if "-j DNAT" not in ln:
            continue
        mp = re.search(r"-p\s+(\w+)", ln)
        md = re.search(r"--dport\s+([\d:]+)", ln)
        mt = re.search(r"--to-destination\s+(\S+)", ln)
        if md:
            out.append((mp.group(1) if mp else "?",
                        md.group(1),
                        mt.group(1) if mt else "?"))
    return out

def dnat_busy_ports():
    """DNAT 已占用的本地端口集合, 给端口冲突展示用"""
    busy = set()
    for _proto, dport, _t in dnat_rules():
        try:
            if ":" in dport:
                a, b = dport.split(":", 1)
                a, b = int(a), int(b)
                if b - a > 5000:
                    b = a + 5000
                for p in range(a, b + 1):
                    busy.add(p)
            else:
                busy.add(int(dport))
        except Exception:
            continue
    return busy

def forward_status(ctx):
    """菜单 17: 只看不改的转发环境总览 + 端口冲突展示"""
    print("")
    line()
    info("转发环境检查")
    line()
    hn = socket.gethostname()
    hit, _ = _hosts_has(hn)
    print("hosts        127.0.1.1 %-24s %s" % (
        hn, "[已配置]" if hit else C_Y + "[缺失]" + C_0))
    rc, ver = run("iptables -V 2>/dev/null", check=False, timeout=15)
    v = (ver or "").strip().split("\n")[0]
    print("iptables     %-36s %s" % (
        v[:36] if rc == 0 else "-", "[已安装]" if rc == 0 else C_Y + "[未安装]" + C_0))
    rc2, cur = run("sysctl -n net.ipv4.ip_forward 2>/dev/null", check=False, timeout=15)
    cur = (cur or "").strip()
    print("ip_forward   %-36s %s" % (
        cur or "-", "[已开启]" if cur == "1" else C_Y + "[未开启]" + C_0))
    rc3, act = run("systemctl is-active dnat 2>/dev/null", check=False, timeout=15)
    rc4, ena = run("systemctl is-enabled dnat 2>/dev/null", check=False, timeout=15)
    act = (act or "").strip() or "-"
    ena = (ena or "").strip() or "-"
    print("dnat 服务    %s / %s" % (act, ena))
    rules = dnat_rules()
    print("")
    if rules:
        info("当前 DNAT 规则 (%d 条):" % len(rules))
        for proto, dport, tgt in rules[:40]:
            info("  %-4s dport %-12s -> %s" % (proto, dport, tgt))
        if len(rules) > 40:
            info("  ... 还有 %d 条" % (len(rules) - 40))
    else:
        info("当前没有 DNAT 规则")
    if os.path.exists("/etc/dnat/conf"):
        try:
            with open("/etc/dnat/conf", "r", encoding="utf-8", errors="ignore") as f:
                cf = [x.strip() for x in f.read().split("\n") if x.strip()]
            print("")
            info("/etc/dnat/conf (%d 条):" % len(cf))
            for x in cf[:40]:
                info("  " + x)
        except Exception as e:
            warn("读 /etc/dnat/conf 失败: %s" % e)
    busy = dnat_busy_ports()
    mine = []
    for m in (ctx.get("related") or []):
        sp = m.get("server_port")
        try:
            sp = int(sp)
        except Exception:
            continue
        if sp > 1:
            mine.append((sp, m.get("id"), m.get("name")))
    print("")
    if mine:
        info("本机节点端口 (%d 个):" % len(mine))
        for sp, nid, nm in mine:
            info("  %-6d id=%-6s %s" % (sp, nid, str(nm)[:30]))
    hops = load_hop_rules()
    if hops:
        info("HY2 跳跃段:")
        for a, b, p in hops:
            info("  %d-%d -> %d" % (a, b, p))
    print("")
    clash = [x for x in mine if x[0] in busy]
    hopclash = [(a, b, p) for a, b, p in hops
                if any(a <= q <= b for q in busy)]
    if clash or hopclash:
        warn("发现端口冲突:")
        for sp, nid, nm in clash:
            warn("  节点端口 %d (id=%s %s) 已被 DNAT 占用" % (sp, nid, str(nm)[:24]))
        for a, b, p in hopclash:
            warn("  跳跃段 %d-%d 与 DNAT 端口重叠" % (a, b))
        info("DNAT 优先级高于本机监听, 撞了的话节点会静默失联")
        info("脚本不会自动改, 请自己调整 /etc/dnat/conf 或换节点端口")
    else:
        ok("端口冲突检查: 无冲突")
    line()
    pause()

def valid_hostname(s):
    """RFC1123 主机名校验"""
    if not s or len(s) > 63:
        return False
    if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$", s):
        return False
    return True

def change_hostname(ctx):
    """菜单 18: 改本机主机名, 改完可选批量改面板节点名"""
    old = socket.gethostname()
    print("")
    line()
    info("修改本机主机名")
    line()
    info("当前主机名: " + C_G + old + C_0)
    print("")
    info("主机名会影响本机节点识别 (节点名含主机名 = 强证据)")
    info("只能用 字母 数字 减号, 不超过 63 位")
    print("")
    new = ask("新主机名 (回车取消)", "")
    if not new:
        info("已取消"); pause(); return
    if new == old:
        info("和当前一样, 无需修改"); pause(); return
    if not valid_hostname(new):
        err("主机名不合法: 只能用 字母/数字/减号, 不能以减号开头结尾, 不超过 63 位")
        pause(); return
    print("")
    warn("将把主机名 %s 改为 %s" % (old, new))
    info("会做这些事: hostnamectl 立即生效 + 写 /etc/hostname + 补 /etc/hosts")
    info("不会重启机器")
    if not confirm("确认修改", False):
        info("已取消"); pause(); return
    rc, out = run("hostnamectl set-hostname %s 2>&1" % new, check=False, timeout=60)
    if rc != 0:
        run("echo %s > /etc/hostname" % new, check=False, timeout=30)
        run("hostname %s >/dev/null 2>&1" % new, check=False, timeout=30)
    now = socket.gethostname()
    if now != new:
        warn("主机名当前读到的还是 %s" % now)
        warn("某些容器不允许改主机名, 或需要重启才生效")
    else:
        ok("主机名已改为 %s" % new)
    fix_hosts(new, verbose=True)
    ctx["hostname"] = now
    print("")
    warn("注意: 面板上已有的节点名还是旧主机名 %s" % old)
    info("节点识别靠 config.json 的 NodeID 兜底, 不会立刻失效")
    info("但名字里带旧主机名的节点, 下次就认不出 名字 这一路证据了")
    aff = []
    try:
        nodes = ctx.get("all_nodes") or get_nodes()
        ctx["all_nodes"] = nodes
        lo = old.lower()
        for m in (ctx.get("related") or []):
            nm = str(m.get("name") or "")
            if lo and lo in strip_sep(nm).lower() and m.get("on_panel"):
                aff.append(m)
    except Exception as e:
        warn("读取面板节点失败: %s" % e)
    if not aff:
        print("")
        info("本机相关节点里没有名字含旧主机名的, 无需改名")
        probe(ctx)
        pause(); return
    print("")
    info("以下 %d 个面板节点名字里含旧主机名:" % len(aff))
    for m in aff:
        nm = str(m.get("name") or "")
        info("  id=%-6s %-32s -> %s" % (
            m.get("id"), nm[:32], _rename_hostname(nm, old, new)[:32]))
    print("")
    if not confirm("要不要把这些节点名一起改成新主机名", False):
        info("已跳过, 面板节点名保持不变")
        probe(ctx)
        pause(); return
    done = fail = 0
    for m in aff:
        nm = str(m.get("name") or "")
        newnm = _rename_hostname(nm, old, new)
        if newnm == nm:
            continue
        node = node_by_id(ctx.get("all_nodes") or [], m.get("id"))
        if not node:
            warn("id=%s 面板取不到, 跳过" % m.get("id")); fail += 1; continue
        try:
            rename_node(node, newnm)
            ok("id=%-6s -> %s" % (m.get("id"), newnm))
            done += 1
        except Exception as e:
            err("id=%s 改名失败: %s" % (m.get("id"), e)); fail += 1
        time.sleep(0.3)
    print("")
    ok("改名完成: 成功 %d 个, 失败 %d 个" % (done, fail))
    probe(ctx)
    pause()

def _rename_hostname(name, old, new):
    """把节点名里的旧主机名换成新主机名, 大小写不敏感, 只换第一处"""
    if not old:
        return name
    i = name.lower().find(old.lower())
    if i < 0:
        return name
    return name[:i] + new + name[i + len(old):]

def rename_node(node, newname):
    """只改 name, 其余字段原样回填"""
    p = {
        "id": int(node.get("id")),
        "name": newname,
        "type": node.get("type"),
        "host": node.get("host"),
        "port": str(node.get("port")),
        "server_port": int(node.get("server_port")),
        "group_ids": node.get("group_ids") or GROUP_IDS,
        "rate": str(node.get("rate") or "1"),
        "show": 1 if node.get("show") in (1, True, None) else 0,
        "tags": node.get("tags") or [],
        "protocol_settings": node.get("protocol_settings") or {},
    }
    if node.get("parent_id"):
        p["parent_id"] = int(node["parent_id"])
    save_node(p)
    return True

def ensure_chrony():
    rc, out = run("which chronyd", check=False, timeout=15)
    if rc != 0:
        info("安装 chrony 校时 (SS2022 对时间敏感) ...")
        run("DEBIAN_FRONTEND=noninteractive apt-get install -y chrony",
            check=False, timeout=300)
    run("systemctl enable --now chrony >/dev/null 2>&1", check=False, timeout=60)
    ok("时间同步已启用")

# ==================== 状态文件 ====================
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(d):
    try:
        os.makedirs(V2BX_DIR, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def state_set(**kw):
    st = load_state()
    st.update(kw)
    st["ts"] = int(time.time())
    save_state(st)

# ==================== 节点 payload 构造 ====================
def used_ports(ctx):
    """本机已占用的端口: 本机相关节点的 server_port + 本地监听
    v0.3: 范围从 config.json 扩到 related (含分割线/复制节点)"""
    u = set()
    for m in ctx.get("related", []) or ctx.get("matched", []):
        try:
            u.add(int(m.get("server_port") or 0))
        except Exception:
            pass
    rc, out = run("ss -tuln 2>/dev/null", check=False, timeout=20)
    for mm in re.finditer(r":(\d{2,5})\s", out):
        u.add(int(mm.group(1)))
    u.discard(0)
    u.discard(1)
    return u

def rand_port(used):
    for _ in range(500):
        p = random.randint(PORT_MIN, PORT_MAX)
        if p not in used:
            used.add(p)
            return p
    die("随机端口分配失败")

def pick_port(ctx, label, used):
    """回车=随机, 也可手填"""
    p = rand_port(used)
    while True:
        s = ask("%s 端口 (回车用随机, 或手填)" % label, str(p))
        if not s.isdigit():
            err("请输入数字"); continue
        v = int(s)
        if not (1 <= v <= 65535):
            err("端口范围 1-65535"); continue
        if v != p and v in used:
            if not confirm("端口 %d 本机似乎已被占用, 仍然使用" % v, False):
                continue
        used.add(v)
        return v

def pl_common(name, host, port, server_port, rate=1, show=1, group_ids=None):
    return {
        "name": name,
        "host": host,
        "port": str(port),
        "server_port": int(server_port),
        "group_ids": group_ids or GROUP_IDS,
        "rate": str(rate),
        "show": int(show),
        "tags": [],
    }

def pl_separator(code):
    p = pl_common("------%s------" % code, "127.0.0.1", 1, 1, 1, 1)
    p["type"] = "shadowsocks"
    p["protocol_settings"] = {"cipher": "aes-128-gcm", "obfs": None, "obfs_settings": None}
    return p

def pl_vless(name, host, port, priv, pub, sid):
    p = pl_common(name, host, port, port)
    p["type"] = "vless"
    p["protocol_settings"] = {
        "tls": 2,
        "network": "tcp",
        "flow": "xtls-rprx-vision",
        "tls_settings": {"server_name": REALITY_SNI, "allow_insecure": 0},
        "network_settings": {},
        "reality_settings": {
            "server_name": REALITY_SNI,
            "server_port": 443,
            "private_key": priv,
            "public_key": pub,
            "short_id": sid,
            "allow_insecure": 0
        }
    }
    return p

def pl_hy2(name, host, port, hop_start, hop_end):
    # port 字段写跳跃段, server_port 写真实监听端口
    p = pl_common(name, host, "%d-%d" % (hop_start, hop_end), port)
    p["type"] = "hysteria"
    p["protocol_settings"] = {
        "version": 2,
        "bandwidth": {"up": None, "down": None},
        "obfs": {"open": False, "type": "salamander", "password": None},
        "tls": {"server_name": CERT_DOMAIN, "allow_insecure": True},
        "hop_interval": None
    }
    return p

def pl_ss22(name, host, port, password):
    p = pl_common(name, host, port, port)
    p["type"] = "shadowsocks"
    p["protocol_settings"] = {
        "cipher": "2022-blake3-aes-128-gcm",
        "server_key": password,
        "obfs": None,
        "obfs_settings": None
    }
    return p

def create_and_fetch(payload, built):
    """建节点 -> 回查拿真实 id. 失败不回滚, 只抛错"""
    name = payload["name"]
    before = get_nodes()
    dup = find_node_by_name(before, name)
    if dup:
        ids = ",".join(str(d.get("id")) for d in dup)
        raise RuntimeError("面板已存在同名节点 %s (id=%s), 请先处理" % (name, ids))
    save_node(payload)
    time.sleep(0.6)
    after = get_nodes()
    hit = find_node_by_name(after, name)
    if not hit:
        raise RuntimeError("节点 %s 建好了但回查不到, 请到面板检查" % name)
    if len(hit) > 1:
        raise RuntimeError("节点 %s 回查到多条, 请到面板检查" % name)
    nid = hit[0].get("id")
    built.append({"id": nid, "name": name})
    ok("已建 %s  id=%s" % (name, nid))
    return nid

# ==================== 编号识别 ====================
SEP_RE = re.compile(r"^-+(.+?)-+$")

def strip_sep(name):
    """------5011-Bero-DE------  ->  5011-Bero-DE"""
    if not name:
        return ""
    m = SEP_RE.match(name.strip())
    return m.group(1).strip() if m else name.strip()

def is_separator(n):
    """分割线判定: 名字被 --- 包住, 或 host=127.0.0.1 且 server_port<=1"""
    nm = str(n.get("name") or "").strip()
    if SEP_RE.match(nm):
        return True
    try:
        return (str(n.get("host")) == "127.0.0.1"
                and int(n.get("server_port") or 0) <= 1)
    except Exception:
        return False

# v0.6 协议关键字表. 必须整段全等才算, 大小写不敏感.
# 特别注意: 绝不能有裸 "ss", 否则 SS-Tokyo / Boss 之类会被误命中.
PROTO_WORDS = set(["vless", "hy2", "hysteria", "hysteria2",
                   "ss22", "ss2022", "shadowsocks", "trojan", "vmess"])

def split_name(name):
    """v0.6 命名规范解析: 编号-主机名-协议-备注

    协议段用"整段全等"定位, 不数 - 的个数, 所以主机名里有多少个 - 都不影响.
    协议段之前是主机名, 之后一律算备注 (含 复制2 / 2 这类).

    例:
      613-YxVM-HK-VOL-VLESS      -> ('613', 'YxVM-HK-VOL', 'vless', '')
      613-HK-01-SS22-复制2       -> ('613', 'HK-01', 'ss22', '复制2')
      613-HK-01-HY2-2            -> ('613', 'HK-01', 'hy2', '2')
      ------613-YxVM-HK-VOL----- -> ('613', 'YxVM-HK-VOL', '', '')
    认不出编号返回 ('','','','')"""
    s = strip_sep(name)
    if not s:
        return "", "", "", ""
    m = re.match(r"^(\d+)-(.+)$", s)
    if not m:
        return "", "", "", ""
    num = m.group(1)
    parts = m.group(2).split("-")
    # 从右往左找协议段, 取最靠右的那个, 避免主机名里的词干扰
    idx = -1
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].strip().lower() in PROTO_WORDS:
            idx = i
            break
    if idx < 0:
        return num, "-".join(parts).strip("-"), "", ""
    hostpart = "-".join(parts[:idx]).strip("-")
    proto = parts[idx].strip().lower()
    note = "-".join(parts[idx + 1:]).strip("-")
    return num, hostpart, proto, note

def parse_code(name):
    """兼容旧接口: 返回 (编号, 编号-主机名).
    v0.6 起底层走 split_name, 协议整段全等识别."""
    num, hostpart, proto, note = split_name(name)
    if not num:
        return "", ""
    if not hostpart:
        return num, num
    return num, "%s-%s" % (num, hostpart)

def guess_code(matched, hostname):
    """从本机已匹配的节点里推断编号. 取出现次数最多的那个完整标识"""
    tally = {}
    for m in matched:
        num, full = parse_code(m.get("name") or "")
        if full:
            tally[full] = tally.get(full, 0) + 1
    if not tally:
        return ""
    # v0.4: 平票时优先选"后缀剥得更干净"的(解析后更短), 再按字母序兜底
    best = sorted(tally.items(), key=lambda kv: (-kv[1], len(kv[0]), kv[0]))[0][0]
    return best

# ==================== 启动探测 (v0.3 重写) ====================
def build_related(ctx, nodes):
    """v0.4 核心改动 1: 强证据优先, IP 只做兜底

       强证据 (三路并集):
         A. conf  : config.json 里在跑的 NodeID  -> 比对面板节点目录
         B. name  : 节点名里含本机主机名子串
         C. code  : 节点名解析出的编号 == 本机编号 -> 抓分割线
         D. child : parent_id 属于 A/B/C         -> 抓复制节点

       弱证据 (兜底):
         E. host  : 面板 host == 本机出口 IP
                    仅当 A/B/C/D 全空时才启用, 且逐条标记 [IP匹配·仅供参考]
                    中转/落地机的 IP 会被别的机器节点借用, 直接采信必然误判
    """
    host = str(ctx.get("host") or "")
    code = str(ctx.get("code") or "")
    hostname = str(ctx.get("hostname") or "").strip()
    local_ids = set(i for i, _ in ctx.get("local_ids", []))
    core_by_id = dict((i, t) for i, t in ctx.get("local_ids", []))
    by_id = {}
    for n in nodes:
        try:
            by_id[int(n.get("id"))] = n
        except Exception:
            pass
    picked = {}
    def take(n, src):
        try:
            i = int(n.get("id"))
        except Exception:
            return
        if i in picked:
            if src not in picked[i]["src"]:
                picked[i]["src"].append(src)
            return
        picked[i] = {"n": n, "src": [src]}
    # ---- A: config.json 里在跑的 NodeID (最强证据) ----
    for i in local_ids:
        if i in by_id:
            take(by_id[i], "conf")
    # ---- B: 节点名含本机主机名 (强证据) ----
    if hostname and len(hostname) >= 3:
        hl = hostname.lower()
        for n in nodes:
            nm = str(n.get("name") or "")
            if hl in strip_sep(nm).lower():
                take(n, "name")
    # ---- C: 节点名解析出的编号 == 本机编号 (强证据, 主要抓分割线) ----
    if code:
        for n in nodes:
            num, full = parse_code(n.get("name") or "")
            if full and full == code:
                take(n, "code")
    # ---- D: parent_id 属于 A/B/C 的复制节点 (强证据) ----
    base = set(picked.keys())
    for n in nodes:
        pid = n.get("parent_id")
        if pid is None or pid == "":
            continue
        try:
            if int(pid) in base:
                take(n, "child")
        except Exception:
            pass
    # ---- E: IP 兜底. 前面全空才用, 否则一律不采信 ----
    ctx["ip_fallback"] = False
    if not picked and host and host != "127.0.0.1":
        for n in nodes:
            if str(n.get("host")) == host:
                take(n, "host")
        if picked:
            ctx["ip_fallback"] = True
            # 兜底命中的也要把它们的复制节点带上
            base2 = set(picked.keys())
            for n in nodes:
                pid = n.get("parent_id")
                if pid is None or pid == "":
                    continue
                try:
                    if int(pid) in base2:
                        take(n, "child")
                except Exception:
                    pass
    rel = []
    for i in sorted(picked.keys()):
        n = picked[i]["n"]
        src = picked[i]["src"]
        in_conf = i in local_ids
        kind = "普通"
        if n.get("parent_id"):
            kind = "复制"
        elif is_separator(n):
            kind = "分割线"
        nm_has_host = bool(hostname) and (hostname.lower()
                          in strip_sep(str(n.get("name") or "")).lower())
        rel.append({
            "id": i,
            "name": n.get("name"),
            "type": n.get("type"),
            "core_type": core_by_id.get(i, CORE_TYPE.get(n.get("type"), "?")),
            "host": n.get("host"),
            "port": n.get("port"),
            "server_port": n.get("server_port"),
            "show": n.get("show"),
            "rate": n.get("rate"),
            "parent_id": n.get("parent_id"),
            "in_conf": in_conf,
            "kind": kind,
            "src": src,
            "weak": ("host" in src) and ("conf" not in src)
                    and ("name" not in src) and ("code" not in src),
            "no_hostname": (not nm_has_host) and kind == "普通",
            "on_panel": True,
        })
    # config.json 里有但面板上没有的, 单独补一条
    for i, t in ctx.get("local_ids", []):
        if i in by_id:
            continue
        rel.append({
            "id": i, "name": "<面板上找不到>" if not ctx.get("panel_err")
                             else "<面板查询失败>",
            "type": t, "core_type": t, "host": "", "port": "",
            "server_port": "", "show": None, "rate": "", "parent_id": None,
            "in_conf": True, "kind": "普通", "src": ["conf"],
            "weak": False, "no_hostname": False, "on_panel": False,
        })
    rel.sort(key=lambda x: (0 if x["kind"] == "分割线" else 1, x["id"]))
    return rel

def probe(ctx):
    print("")
    print("正在检查本机状态 ...")
    ctx["installed"] = v2bx_installed()
    ctx["running"]   = v2bx_running()
    conf = load_v2bx_conf()
    ctx["conf"] = conf
    ctx["local_ids"] = []
    if conf and conf.get("Nodes"):
        for n in conf["Nodes"]:
            if n.get("NodeID") is not None:
                ctx["local_ids"].append((int(n["NodeID"]), n.get("NodeType", "?")))
    ctx["matched"] = []
    ctx["related"] = []
    ctx["panel_err"] = ""
    ctx["all_nodes"] = []
    try:
        nodes = get_nodes()
        ctx["all_nodes"] = nodes
    except Exception as e:
        nodes = []
        ctx["panel_err"] = str(e)
        warn("读取面板节点列表失败: %s" % e)
    by_id = {}
    for n in nodes:
        try:
            by_id[int(n.get("id"))] = n
        except Exception:
            pass
    # matched = config.json 里的节点 (老逻辑, 供管理菜单用)
    for nid, ntype in ctx["local_ids"]:
        n = by_id.get(nid)
        if n:
            ctx["matched"].append({
                "id": nid, "core_type": ntype,
                "name": n.get("name"), "type": n.get("type"),
                "host": n.get("host"), "port": n.get("port"),
                "server_port": n.get("server_port"),
                "show": n.get("show"), "rate": n.get("rate"),
                "on_panel": True})
        else:
            miss = "<面板上找不到>" if not ctx["panel_err"] else "<面板查询失败>"
            ctx["matched"].append({
                "id": nid, "core_type": ntype, "name": miss,
                "type": ntype, "host": "", "port": "", "server_port": "",
                "show": None, "rate": "", "on_panel": False})
    # 编号: state 优先, 其次从已匹配节点名推断
    st = load_state()
    ctx["code"] = st.get("code", "") or ""
    if not ctx["code"]:
        ctx["code"] = guess_code(ctx["matched"], ctx["hostname"])
        if ctx["code"]:
            ctx["code_guessed"] = True
    # host: state 优先, 其次从已匹配节点取
    if not ctx.get("host"):
        ctx["host"] = st.get("host", "") or ""
    if not ctx.get("host"):
        for m in ctx["matched"]:
            if m.get("host") and m.get("host") != "127.0.0.1":
                ctx["host"] = m["host"]; break
    # v0.3: 四路并集
    ctx["related"] = build_related(ctx, nodes)
    ctx["is_new"] = (len(ctx["local_ids"]) == 0)

def fmt_port(m):
    """v0.3 核心改动 1: 端口显示. HY2 显示 真实口(跳跃段)"""
    sp = m.get("server_port")
    pt = str(m.get("port") or "")
    if m.get("kind") == "分割线":
        return "-"
    if not sp and not pt:
        return "?"
    if "-" in pt:
        return "%s (跳跃 %s)" % (sp, pt)
    return str(sp or pt or "?")

def print_header(ctx):
    os.system("clear")
    print(C_B + "=" * 60 + C_0)
    print(C_B + "XBoard 节点部署脚本  v0.7" + C_0)
    print(C_B + "=" * 60 + C_0)
    print("主机名   : %s" % ctx["hostname"])
    print("出口地址 : %s" % ctx.get("host", "(未选择)"))
    print("面板     : %s" % PANEL_URL)
    print("V2bX     : %s / %s" % (
        "已安装" if ctx["installed"] else "未安装",
        (C_G + "运行中" + C_0) if ctx["running"] else (C_Y + "未运行" + C_0)))
    line()
    rel = ctx.get("related") or []
    if rel:
        n_conf = len([r for r in rel if r["in_conf"]])
        print("本机相关节点 %d 个  (其中 config.json 里 %d 个):" % (len(rel), n_conf))
        for m in rel:
            tag = ""
            if m["kind"] == "分割线":
                tag += C_B + " [分割线]" + C_0
            elif m["kind"] == "复制":
                tag += C_B + " [子]" + C_0
            if m.get("weak"):
                tag += C_Y + " [IP匹配·仅供参考]" + C_0
            elif not m["in_conf"] and m["kind"] == "普通":
                tag += C_Y + " [仅面板]" + C_0
            if m.get("no_hostname") and not m.get("weak"):
                tag += C_Y + " [名字不含主机名]" + C_0
            if not m["on_panel"]:
                tag += C_R + " [面板无此节点]" + C_0
            elif m["show"] in (0, False):
                tag += C_Y + " [隐藏]" + C_0
            print("  id=%-6s %-6s %-30s 端口 %-18s%s" % (
                m["id"], TYPE_CN.get(m["type"], m["core_type"]),
                str(m["name"])[:30], fmt_port(m), tag))
    else:
        print(C_Y + "本机没有检测到 V2bX 节点配置 -> 判定为新机器" + C_0)
    line()
    c = ctx.get("code")
    if c and ctx.get("code_guessed"):
        print("机器编号 : %s%s%s  (从已有节点识别)" % (C_G, c, C_0))
    elif c:
        print("机器编号 : %s" % c)
    else:
        print("机器编号 : " + C_Y + "(未设置)" + C_0)
    hops = load_hop_rules()
    if hops:
        print("跳跃规则 : " + ", ".join("%d-%d->%d" % (a, b, p) for a, b, p in hops))
    print(C_B + "=" * 60 + C_0)

def ensure_code(ctx, force=False, allow_skip=False):
    """allow_skip=True 时, 直接回车(且没有默认值)就返回 "" 表示跳过"""
    if ctx.get("code") and not force:
        return ctx["code"]
    print("")
    info("编号规则: 数字编号 + 主机名. 推荐 5 位: 前两位区域, 后三位区域内顺序")
    info("20=香港  30=亚太  40=美国  50=欧洲  60+=其他   例 20010 = 香港第 10 台")
    cur = ctx.get("code", "")
    curnum = ""
    m = re.match(r"^(\d+)-", cur or "")
    if m:
        curnum = m.group(1)
    while True:
        if allow_skip and not curnum:
            c = ask("请输入本机编号 (例 20010) [回车=跳过]", "")
            if not c:
                return ""
        else:
            c = ask("请输入本机编号 (例 20010)", curnum)
        if not c.isdigit():
            err("编号必须是纯数字")
            continue
        if not (2 <= len(c) <= 6):
            err("编号长度只支持 2-6 位, 当前 %d 位" % len(c))
            continue
        break
    full = "%s-%s" % (c, ctx["hostname"])
    print("")
    info("将使用标识: " + C_G + full + C_0)
    info("分割线   ------%s------" % full)
    info("VLESS    %s-VLESS" % full)
    info("HY2      %s-HY2" % full)
    info("SS22     %s-SS22" % full)
    if not confirm("确认", True):
        return ensure_code(ctx, force=True, allow_skip=allow_skip)
    ctx["code"] = full
    ctx["code_guessed"] = False
    state_set(code=full)
    return full

def next_free_name(nodes, base):
    """base 已存在就试 base-2 base-3 ..."""
    if not find_node_by_name(nodes, base):
        return base
    for i in range(2, 60):
        cand = "%s-%d" % (base, i)
        if not find_node_by_name(nodes, cand):
            return cand
    raise RuntimeError("名字 %s 冲突太多" % base)

def find_group_by_code(nodes, num):
    """按编号找出面板上属于这个编号的所有节点(不分主机名).
    返回 [{id,name,type,parent_id,is_sep,full}]
    排序: 复制节点 -> 普通节点 -> 分割线 (先删子再删父, 分割线最后)"""
    num = str(num).strip()
    hit = []
    for n in nodes:
        nm = str(n.get("name") or "")
        c, full = parse_code(nm)
        if c and c == num:
            try:
                nid = int(n.get("id"))
            except Exception:
                continue
            hit.append({
                "id": nid,
                "name": nm,
                "type": n.get("type"),
                "parent_id": n.get("parent_id"),
                "is_sep": is_separator(n),
                "full": full,
            })
    def rank(x):
        if x["is_sep"]:
            return 2
        if x["parent_id"]:
            return 0
        return 1
    hit.sort(key=lambda x: (rank(x), x["id"]))
    return hit


def purge_code_group(num, mine_full):
    """一键部署专用: 删掉面板上编号 == num 的所有节点.
    返回删除条数; 用户取消返回 -1; 面板本来就没有返回 0.
    任何删不干净的情况直接 raise, 绝不带着残留继续建节点."""
    nodes = get_nodes()
    group = find_group_by_code(nodes, num)
    if not group:
        return 0
    print("")
    line()
    warn("面板上已存在编号 %s 的节点, 共 %d 条:" % (num, len(group)))
    print("")
    same_host = 0
    for g in group:
        if g["is_sep"]:
            tag = "  <- 分割线"
        elif g["parent_id"]:
            tag = "  <- 复制节点(parent=%s)" % g["parent_id"]
        else:
            tag = ""
        if g["full"] and g["full"] == mine_full:
            tag += "  " + C_Y + "[与本机标识相同]" + C_0
            same_host += 1
        info("  id=%-8s %s%s" % (g["id"], g["name"], tag))
    print("")
    if same_host == 0:
        warn("注意: 上面没有一条和本机标识 %s 相同" % mine_full)
        warn("说明这些节点属于【另一台机器】, 删掉后那台机器会掉线")
    warn("继续将把以上 %d 条从面板【全部删除】, 然后重建一组新的" % len(group))
    warn("删除后 id 会变 / 老订阅链接失效 / 历史流量清零 / 无法撤销")
    line()
    if not confirm("确认删除这 %d 条并继续部署" % len(group), False):
        return -1
    print("")
    done = 0
    for g in group:
        try:
            drop_node(g["id"])
            ok("已删 id=%s  %s" % (g["id"], g["name"]))
            done += 1
        except Exception as e:
            err("删除失败 id=%s  %s  -> %s" % (g["id"], g["name"], e))
    time.sleep(1.0)
    left = find_group_by_code(get_nodes(), num)
    if left:
        print("")
        for g in left:
            err("残留 id=%s  %s" % (g["id"], g["name"]))
        raise RuntimeError("编号 %s 仍有 %d 条没删掉, 已中止部署" % (num, len(left)))
    ok("编号 %s 已从面板清空, 共删除 %d 条" % (num, done))
    return done


def add_separator(ctx):
    """菜单 14: 只在面板建一条分割线. 不动 config.json, 不重启 V2bX, 不删任何东西."""
    print("")
    line()
    info("新增分割线")
    info("分割线是面板上的占位条目, 只用来在订阅里分组, 不承载流量")
    line()
    cur = ctx.get("code") or ""
    txt = ask("分割线内容 (不用打两边的 -)", cur)
    txt = strip_sep(txt).strip()
    if not txt:
        info("没填内容, 已取消")
        return
    dash = ask_int("两边各几个 -", 6, 1, 30)
    name = "%s%s%s" % ("-" * dash, txt, "-" * dash)
    if len(name) > 60:
        err("名字太长了 (%d 字符), 面板可能存不下, 请缩短" % len(name))
        return
    nodes = get_nodes()
    if find_node_by_name(nodes, name):
        err("面板已存在同名分割线: %s" % name)
        return
    print("")
    info("将新建分割线: " + C_G + name + C_0)
    info("不会写 config.json, 不会重启 V2bX, 不会删除任何节点")
    if not confirm("确认", True):
        info("已取消")
        return
    built = []
    create_and_fetch(pl_separator_raw(name), built)
    print("")
    ok("分割线已建好: %s" % name)


def pl_separator_raw(name):
    """按完整名字建分割线 (pl_separator 是按 code 自动加 ------)"""
    p = pl_common(name, "127.0.0.1", 1, 1, 1, 1)
    p["type"] = "shadowsocks"
    p["protocol_settings"] = {"cipher": "aes-128-gcm", "obfs": None, "obfs_settings": None}
    return p

def restart_v2bx():
    print("")
    info("正在重启 V2bX ...")
    run("systemctl restart V2bX", check=False, timeout=90)
    time.sleep(4)
    if v2bx_running():
        ok("V2bX 运行中")
        return True
    err("V2bX 未启动, 最近日志:")
    rc, out = run("journalctl -u V2bX -n 30 --no-pager", check=False, timeout=30)
    print(out)
    return False

# ==================== 1) 一键部署 ====================
def deploy_all(ctx):
    code = ctx["code"]
    host = ctx["host"]
    built = []
    print("")
    line()
    info("将要部署 (编号 %s, 出口 %s):" % (code, host))
    info("  1. 分割线   ------%s------" % code)
    info("  2. VLESS    %s-VLESS" % code)
    info("  3. HY2      %s-HY2" % code)
    info("  4. SS22     %s-SS22" % code)
    line()
    if not confirm("确认开始部署", True):
        info("已取消"); return
    num = code.split("-")[0]
    try:
        n_del = purge_code_group(num, code)
    except Exception as e:
        die("清理旧编号失败: %s" % e, [])
    if n_del == -1:
        print("")
        info("已取消, 面板没有做任何改动")
        return
    used = used_ports(ctx)
    print("")
    info("端口分配 (回车=随机, 也可手填)")
    p_vless = pick_port(ctx, "VLESS", used)
    p_hy2   = pick_port(ctx, "HY2  ", used)
    p_ss22  = pick_port(ctx, "SS22 ", used)
    hop_s, hop_e = HOP_DEFAULT
    old_rules = load_hop_rules()
    keep_rules = []
    if old_rules:
        ov = hop_overlap(hop_s, hop_e)
        ov_ports = set(p for _a, _b, p in ov)
        print("")
        line()
        warn("本机已有 %d 条 HY2 端口跳跃规则:" % len(old_rules))
        print("")
        for a, b, p in old_rules:
            tag = ""
            if p in ov_ports:
                tag = "  " + C_Y + "[与本次 %d-%d 重叠]" % (hop_s, hop_e) + C_0
            info("  %d-%d -> 端口 %d%s" % (a, b, p, tag))
        print("")
        warn("一键部署会【全量重写】跳跃规则, 默认会把上面这些全部清掉")
        print("")
        info("  1) 用最新的        清掉上面全部, 只保留本次 %d-%d (推荐)" % (hop_s, hop_e))
        info("  2) 保留旧规则      旧的继续留着, 本次自动另换一段")
        info("  3) 手动指定        自己填本次的跳跃段")
        print("")
        ch = ask("选择", "1")
        while ch not in ("1", "2", "3"):
            err("只能填 1 / 2 / 3")
            ch = ask("选择", "1")
        if ch == "2":
            keep_rules = [r for r in old_rules if r[2] != p_hy2]
            hop_s, hop_e = HOP_EXTRA
            if hop_overlap_list(keep_rules, hop_s, hop_e):
                print("")
                warn("备用段 %d-%d 也和保留的规则重叠, 请手动指定" % (hop_s, hop_e))
                while True:
                    hop_s = ask_int("跳跃起始", hop_s, 1024, 65535)
                    hop_e = ask_int("跳跃结束", hop_e, hop_s, 65535)
                    if not hop_overlap_list(keep_rules, hop_s, hop_e):
                        break
                    warn("%d-%d 仍然重叠, 请重填" % (hop_s, hop_e))
            ok("将保留 %d 条旧规则, 本次使用 %d-%d" % (len(keep_rules), hop_s, hop_e))
        elif ch == "3":
            hop_s = ask_int("跳跃起始", hop_s, 1024, 65535)
            hop_e = ask_int("跳跃结束", hop_e, hop_s, 65535)
        else:
            ok("将清空 %d 条旧规则, 只使用 %d-%d" % (len(old_rules), hop_s, hop_e))
    step_total(8)
    step("安装 V2bX")
    if not v2bx_installed():
        install_v2bx()
    else:
        ok("V2bX 已安装, 跳过")
    step_done()
    step("准备证书")
    ensure_cert()
    step_done()
    step("生成 Reality 密钥")
    priv, pub = gen_reality_keypair()
    sid = gen_short_id()
    ok("公钥 " + pub)
    ok("short_id " + sid)
    step_done()
    step("面板建节点")
    try:
        nodes = get_nodes()
        sep_name = "------%s------" % code
        if find_node_by_name(nodes, sep_name):
            raise RuntimeError("清理后分割线 %s 仍存在, 面板状态异常" % sep_name)
        create_and_fetch(pl_separator(code), built)
        id_vless = create_and_fetch(
            pl_vless("%s-VLESS" % code, host, p_vless, priv, pub, sid), built)
        id_hy2 = create_and_fetch(
            pl_hy2("%s-HY2" % code, host, p_hy2, hop_s, hop_e), built)
        pw = gen_ss2022_password()
        id_ss22 = create_and_fetch(
            pl_ss22("%s-SS22" % code, host, p_ss22, pw), built)
    except Exception as e:
        die("建节点失败: %s" % e, built)
    step_done()
    step("写 V2bX 配置")
    entries = [node_entry(id_vless, "vless"),
               node_entry(id_hy2, "hysteria2"),
               node_entry(id_ss22, "shadowsocks")]
    ensure_sing_origin()
    write_v2bx_conf(entries, replace_all=True)
    step_done()
    step("配置 HY2 端口跳跃")
    write_nft_hop(keep_rules + [(hop_s, hop_e, p_hy2)], hard=False)
    step_done()
    step("时间同步")
    ensure_chrony()
    step_done()
    step("转发环境")
    ensure_forward()
    step_done()
    step("启动 V2bX")
    run("systemctl enable V2bX >/dev/null 2>&1", check=False, timeout=30)
    running = restart_v2bx()
    step_done()
    state_set(code=code, host=host,
              ports={"vless": p_vless, "hy2": p_hy2, "ss22": p_ss22},
              reality_public_key=pub, short_id=sid,
              hops=[[a, b, p] for a, b, p in keep_rules] + [[hop_s, hop_e, p_hy2]])
    print("")
    line()
    ok("部署完成")
    info("编号     %s" % code)
    info("出口     %s" % host)
    info("VLESS    id=%s  端口 %d" % (id_vless, p_vless))
    info("HY2      id=%s  端口 %d  跳跃 %d-%d" % (id_hy2, p_hy2, hop_s, hop_e))
    info("SS22     id=%s  端口 %d" % (id_ss22, p_ss22))
    info("Reality  公钥 %s  short_id %s" % (pub, sid))
    if not running:
        warn("V2bX 没起来, 用菜单 9 重启或看日志")
    line()

# ==================== 2/3/4) 新增单个节点 ====================
def add_node(ctx, kind):
    if not ctx.get("host"):
        ctx["host"] = choose_ip(ctx)
    ensure_code(ctx)
    code = ctx["code"]
    host = ctx["host"]
    if not v2bx_installed():
        warn("V2bX 还没装, 先用菜单 1 一键部署")
        return
    label = {"vless": "VLESS", "hy2": "HY2", "ss22": "SS22"}[kind]
    nodes = get_nodes()
    base = "%s-%s" % (code, label)
    default_name = next_free_name(nodes, base)
    print("")
    line()
    info("新增 %s 节点" % label)
    line()
    name = ask("节点名", default_name)
    if find_node_by_name(nodes, name):
        err("面板已存在同名节点 %s" % name); return
    used = used_ports(ctx)
    port = pick_port(ctx, label, used)
    hop_s = hop_e = None
    if kind == "hy2":
        hop_s, hop_e = HOP_EXTRA
        ov = hop_overlap(hop_s, hop_e)
        if ov:
            print("")
            warn("默认跳跃段 %d-%d 与本机已有规则重叠:" % (hop_s, hop_e))
            for a, b, p in ov:
                info("  已有 %d-%d -> %d" % (a, b, p))
            warn("脚本不会自动换段, 请自己决定")
            info("已有规则可以在菜单 8 查看. 60000-65535 被占满时可以往下用 55000 段")
        hop_s = ask_int("跳跃起始", hop_s, 1024, 65535)
        hop_e = ask_int("跳跃结束", hop_e, hop_s, 65535)
        ov2 = hop_overlap(hop_s, hop_e)
        if ov2:
            warn("你填的 %d-%d 仍然和已有规则重叠" % (hop_s, hop_e))
            if not confirm("确定要这样加吗", False):
                info("已取消"); return
    print("")
    info("将新增: %s  端口 %d%s" % (
        name, port,
        ("  跳跃 %d-%d" % (hop_s, hop_e)) if kind == "hy2" else ""))
    info("会追加到 config.json 并重启 V2bX, 已有节点不受影响")
    if not confirm("确认", True):
        info("已取消"); return
    built = []
    if kind == "vless":
        priv, pub = gen_reality_keypair()
        sid = gen_short_id()
        nid = create_and_fetch(pl_vless(name, host, port, priv, pub, sid), built)
        entry = node_entry(nid, "vless")
        info("Reality 公钥: " + pub)
        info("short_id   : " + sid)
    elif kind == "hy2":
        ensure_cert()
        nid = create_and_fetch(pl_hy2(name, host, port, hop_s, hop_e), built)
        entry = node_entry(nid, "hysteria2")
    else:
        pw = gen_ss2022_password()
        nid = create_and_fetch(pl_ss22(name, host, port, pw), built)
        entry = node_entry(nid, "shadowsocks")
    write_v2bx_conf([entry], replace_all=False)
    if kind == "hy2":
        add_hop_rule(hop_s, hop_e, port)
    restart_v2bx()
    ok("新增完成: %s  id=%s  端口 %d" % (name, nid, port))

# ==================== 5) 复制节点 ====================
def copy_node(ctx):
    """面板建一个 parent_id 子节点, 订阅里多一条一模一样的.
    不动 config.json, 不重启 V2bX"""
    print("")
    line()
    info("复制节点: 在面板建一条和源节点完全一样的 (端口也一样)")
    info("走 parent_id 子节点, 共用源节点的流量与密钥, 本机不用改任何配置")
    line()
    nodes = get_nodes()
    cand = [r for r in (ctx.get("related") or []) if r["kind"] != "分割线"]
    if cand:
        info("本机相关节点:")
        for m in cand:
            print("  id=%-6s %-6s %-30s 端口 %s" % (
                m["id"], TYPE_CN.get(m["type"], m["core_type"]),
                str(m["name"])[:30], fmt_port(m)))
        print("")
    sid_in = ask("要复制的源节点 id (可填本机以外的任意 id)")
    if not sid_in.isdigit():
        err("必须是数字 id"); return
    src = node_by_id(nodes, int(sid_in))
    if not src:
        err("面板上找不到 id=%s" % sid_in); return
    print("")
    info("源节点:")
    info("  id          : %s" % src.get("id"))
    info("  name        : %s" % src.get("name"))
    info("  type        : %s" % src.get("type"))
    info("  host        : %s" % src.get("host"))
    info("  port        : %s" % src.get("port"))
    info("  server_port : %s" % src.get("server_port"))
    info("  rate        : %s" % src.get("rate"))
    info("  group_ids   : %s" % json.dumps(src.get("group_ids"), ensure_ascii=False))
    base = "%s-复制1" % src.get("name")
    if find_node_by_name(nodes, base):
        for i in range(2, 60):
            cand2 = "%s-复制%d" % (src.get("name"), i)
            if not find_node_by_name(nodes, cand2):
                base = cand2; break
    print("")
    name = ask("新节点名", base)
    rate = ask("倍率", str(src.get("rate") or "1"))
    gids = src.get("group_ids") or GROUP_IDS
    info("分组沿用源节点: %s" % json.dumps(gids, ensure_ascii=False))
    if not confirm("分组保持不变", True):
        g = ask("输入分组 id, 逗号分隔 (例 2,5)", ",".join(str(x) for x in gids))
        gids = [x.strip() for x in g.split(",") if x.strip()]
    p = {
        "name": name,
        "type": src.get("type"),
        "host": src.get("host"),
        "port": str(src.get("port")),
        "server_port": int(src.get("server_port")),
        "group_ids": gids,
        "rate": str(rate),
        "show": 1,
        "tags": src.get("tags") or [],
        "parent_id": int(src.get("id")),
        "protocol_settings": src.get("protocol_settings") or {},
    }
    print("")
    info("将建立子节点: %s  (parent_id=%s)" % (name, src.get("id")))
    info("端口与源节点完全一致, 本机不新增服务, 不重启 V2bX")
    if not confirm("确认", True):
        info("已取消"); return
    built = []
    nid = create_and_fetch(p, built)
    time.sleep(0.6)
    chk = node_by_id(get_nodes(), nid)
    if chk and chk.get("parent_id"):
        ok("复制成功  id=%s  parent_id=%s" % (nid, chk.get("parent_id")))
    else:
        warn("节点建好了 id=%s, 但 parent_id 没写进去, 请到面板检查" % nid)

# ==================== 6) 本机节点管理 ====================
def valid_sni(d):
    """域名基本校验: 只允许字母数字点和连字符, 至少一个点"""
    d = (d or "").strip()
    if not d or len(d) > 253 or "." not in d:
        return False
    return re.match(r"^[A-Za-z0-9.\-]+$", d) is not None

def probe_tls13(domain):
    """探测目标域名是否支持 TLS1.3 (Reality 的硬性前提).
    返回 (是否支持, 说明). 探测本身失败不算不支持, 只是测不出来."""
    rc, out = run("openssl s_client -connect %s:443 -servername %s "
                  "-tls1_3 </dev/null 2>&1 | head -40" % (domain, domain),
                  check=False, timeout=20)
    low = (out or "").lower()
    if "tlsv1.3" in low or "tls_aes" in low:
        return True, "支持 TLS1.3"
    if "connect:errno" in low or "unable to connect" in low:
        return None, "连不上, 测不出来"
    if "wrong version" in low or "no protocols available" in low:
        return False, "不支持 TLS1.3"
    return None, "测不出来"

def local_sni_sync(node_id, new_sni):
    """把本机 config.json 里对应 NodeID 的 CertDomain 同步改掉.
    返回 True 表示确实改了本机文件."""
    conf = load_v2bx_conf()
    if not conf or not conf.get("Nodes"):
        return False
    hit = False
    for e in conf["Nodes"]:
        if int(e.get("NodeID", -1)) != int(node_id):
            continue
        cc = e.get("CertConfig") or {}
        if cc.get("CertDomain") == new_sni:
            hit = True
            continue
        cc["CertDomain"] = new_sni
        e["CertConfig"] = cc
        hit = True
    if not hit:
        return False
    backup_file(V2BX_CONF)
    with open(V2BX_CONF, "w", encoding="utf-8") as fp:
        json.dump(conf, fp, indent=2, ensure_ascii=False)
    return True

def edit_node_sni(node):
    """v0.6 改 SNI. 按节点 type 自动走对应那套:
         vless    -> Reality server_name (+ tls_settings.server_name)
         hysteria -> 证书域名 tls.server_name, 并重签本机自签证书
       只改选中的这一个节点, 不动同机器其他节点."""
    t = str(node.get("type") or "").lower()
    nid = int(node.get("id"))
    ps = node.get("protocol_settings") or {}
    if t == "vless":
        cur = ((ps.get("reality_settings") or {}).get("server_name")
               or (ps.get("tls_settings") or {}).get("server_name") or "")
        print("")
        info("协议 VLESS (Reality)  当前 SNI: %s" % (cur or "(空)"))
        info("Reality 的 SNI 是伪装域名, 必须选一个真实存在、支持 TLS1.3 的站点")
        info("常用: apple.com  www.microsoft.com  www.cloudflare.com")
    elif t == "hysteria":
        cur = ((ps.get("tls") or {}).get("server_name") or "")
        print("")
        info("协议 HY2  当前证书域名: %s" % (cur or "(空)"))
        info("HY2 用的是本机自签证书, 客户端本来就要跳过证书验证")
        info("所以这个域名随便填都能连, 换它只是改外观")
    else:
        err("只有 VLESS 和 HY2 有 SNI 可改, 这个节点是 %s"
            % TYPE_CN.get(t, t))
        return False

    new = ask("新域名 (留空取消)", "")
    if not new:
        info("已取消"); return False
    if not valid_sni(new):
        err("域名格式不对: %s" % new); return False
    if new == cur:
        info("跟当前一样, 不用改"); return False

    if t == "vless":
        okk, why = probe_tls13(new)
        if okk is False:
            err("%s %s -> Reality 用它会连不上" % (new, why))
            if not confirm("还是要用这个域名", False):
                info("已取消"); return False
        elif okk is None:
            warn("%s %s, 请自行确认" % (new, why))
        else:
            ok("%s %s" % (new, why))

    print("")
    warn("将把 id=%s  %s" % (nid, node.get("name")))
    info("  SNI  %s  ->  %s" % (cur or "(空)", new))
    if t == "vless":
        info("  面板改 reality_settings/tls_settings 的 server_name")
        info("  本机 config.json 的 CertDomain 同步改, 然后重启 V2bX")
        info("  Reality 公私钥不变, 客户端只需改 SNI 一项")
    else:
        info("  面板改 tls.server_name")
        info("  本机重新签发自签证书 (CN=%s), config.json 同步, 重启 V2bX" % new)
    if not confirm("确认修改", False):
        info("已取消"); return False

    # 1) 面板
    ps2 = json.loads(json.dumps(ps)) if ps else {}
    if t == "vless":
        rs = ps2.get("reality_settings") or {}
        rs["server_name"] = new
        ps2["reality_settings"] = rs
        ts = ps2.get("tls_settings") or {}
        if ts:
            ts["server_name"] = new
            ps2["tls_settings"] = ts
    else:
        tl = ps2.get("tls") or {}
        tl["server_name"] = new
        ps2["tls"] = tl
    p = {
        "id": nid,
        "name": node.get("name"),
        "type": node.get("type"),
        "host": node.get("host"),
        "port": str(node.get("port")),
        "server_port": int(node.get("server_port")),
        "group_ids": node.get("group_ids") or GROUP_IDS,
        "rate": str(node.get("rate") or "1"),
        "show": 1 if node.get("show") in (1, True, None) else 0,
        "tags": node.get("tags") or [],
        "protocol_settings": ps2,
    }
    if node.get("parent_id"):
        p["parent_id"] = int(node["parent_id"])
    save_node(p)
    ok("面板已更新 id=%s" % nid)

    # 2) HY2 重签证书
    if t == "hysteria":
        try:
            global CERT_DOMAIN
            CERT_DOMAIN = new
            if os.path.exists(CERT_FILE):
                backup_file(CERT_FILE)
                os.remove(CERT_FILE)
            if os.path.exists(KEY_FILE):
                os.remove(KEY_FILE)
            ensure_cert()
            cfg = load_conf() or {}
            if cfg:
                cfg["cert_domain"] = new
                save_conf(cfg)
        except Exception as e:
            err("证书重签失败: %s (面板已改, 本机证书还是旧的)" % e)

    # 3) 本机 config.json
    try:
        if local_sni_sync(nid, new):
            ok("本机 config.json 已同步")
            restart_v2bx()
        else:
            info("本机 config.json 没有这个节点, 只改了面板")
    except Exception as e:
        err("本机同步失败: %s" % e)
    return True

def edit_panel_fields(node):
    """只允许改安全字段. host/port/server_port/protocol_settings 一律不碰"""
    name = ask("名称", node.get("name") or "")
    rate = ask("倍率", str(node.get("rate") or "1"))
    gids = node.get("group_ids") or GROUP_IDS
    g = ask("分组 id (逗号分隔)", ",".join(str(x) for x in gids))
    gids = [x.strip() for x in g.split(",") if x.strip()]
    cur_show = 1 if node.get("show") in (1, True, None) else 0
    sh = ask("显示 1=显示 0=隐藏", str(cur_show))
    p = {
        "id": int(node.get("id")),
        "name": name,
        "type": node.get("type"),
        "host": node.get("host"),
        "port": str(node.get("port")),
        "server_port": int(node.get("server_port")),
        "group_ids": gids,
        "rate": str(rate),
        "show": 1 if str(sh).strip() != "0" else 0,
        "tags": node.get("tags") or [],
        "protocol_settings": node.get("protocol_settings") or {},
    }
    if node.get("parent_id"):
        p["parent_id"] = int(node["parent_id"])
    print("")
    info("将提交: %s  倍率 %s  分组 %s  显示 %s" % (
        p["name"], p["rate"], ",".join(p["group_ids"]), p["show"]))
    info("地址/端口/协议参数不会改动")
    if not confirm("确认保存", True):
        info("已取消"); return False
    save_node(p)
    ok("已保存 id=%s" % p["id"])
    return True

def manage_local(ctx):
    """v0.3: 列表改用 related 全集, 删除时区分 config.json 内外"""
    while True:
        print("")
        line()
        info("本机节点管理 (本机相关的全部节点)")
        line()
        rel = ctx.get("related") or []
        if not rel:
            info("本机没有检测到相关节点")
            pause(); return
        for i, m in enumerate(rel, 1):
            tag = ""
            if m["kind"] == "分割线":
                tag += C_B + " [分割线]" + C_0
            elif m["kind"] == "复制":
                tag += C_B + " [子]" + C_0
            if m.get("weak"):
                tag += C_Y + " [IP匹配·仅供参考]" + C_0
            elif not m["in_conf"] and m["kind"] == "普通":
                tag += C_Y + " [仅面板]" + C_0
            if not m["on_panel"]:
                tag += C_R + " [面板无此节点]" + C_0
            elif m["show"] in (0, False):
                tag += C_Y + " [隐藏]" + C_0
            print("%2d) id=%-6s %-6s %-28s 端口 %-16s%s" % (
                i, m["id"], TYPE_CN.get(m["type"], m["core_type"]),
                str(m["name"])[:28], fmt_port(m), tag))
        print("")
        info("标签说明: [分割线]=占位节点  [子]=复制出来的子节点")
        info("          [仅面板]=面板有但本机 config.json 没跑")
        info("          [面板无此节点]=本机在跑但面板已删  [隐藏]=面板设为不显示")
        info("          [IP匹配·仅供参考]=只靠出口 IP 猜的, 可能是别的机器")
        print("")
        print(" 1) 修改节点 (名称/倍率/分组/显示)")
        print(" 2) 修改 SNI (VLESS 改 Reality 伪装域名, HY2 改证书域名)")
        print(" 3) 删除节点 (面板 + config.json 一起处理)")
        print(" 0) 返回        直接回车也是返回")
        c = ask("选择", "")
        if not c or c == "0":
            return
        if c == "3":
            n = ask_int("要删除的序号", None, 1, len(rel))
            if n is None: continue
            m = rel[n - 1]
            print("")
            warn("将要删除: id=%s  %s" % (m["id"], m["name"]))
            if m["in_conf"]:
                info("面板节点会被删除, config.json 条目会被移除, 然后重启 V2bX")
            else:
                info("这个节点不在 config.json 里, 只会删面板, 本机不重启")
            if not confirm("确认删除", False):
                info("已取消"); continue
            try:
                if m["on_panel"]:
                    drop_node(m["id"])
                    ok("面板节点已删除 id=%s" % m["id"])
                if m["in_conf"]:
                    remove_from_conf(m["id"])
                    if m.get("type") == "hysteria" and m.get("server_port"):
                        del_hop_rule(m["server_port"])
                    restart_v2bx()
            except Exception as e:
                err("删除失败: %s" % e)
            probe(ctx)
            pause()
        elif c in ("1", "2"):
            n = ask_int("要修改的序号", None, 1, len(rel))
            if n is None: continue
            m = rel[n - 1]
            if not m["on_panel"]:
                err("这个节点在面板上不存在, 改不了"); pause(); continue
            node = node_by_id(ctx.get("all_nodes") or get_nodes(), m["id"])
            if not node:
                err("重新获取节点失败"); pause(); continue
            print("")
            try:
                if c == "1":
                    done = edit_panel_fields(node)
                else:
                    done = edit_node_sni(node)
                if done:
                    ctx["all_nodes"] = get_nodes()
                    probe(ctx)
            except Exception as e:
                err("保存失败: %s" % e)
            pause()
        else:
            err("没有这个选项: %s" % c); pause()

# ==================== 7) 面板节点浏览 ====================
def browse_panel(ctx):
    try:
        nodes = get_nodes()
    except Exception as e:
        err("读取面板失败: %s" % e); pause(); return
    ctx["all_nodes"] = nodes
    kw = ""
    while True:
        show = nodes
        if kw:
            k = kw.lower()
            show = [n for n in nodes
                    if k in str(n.get("name", "")).lower()
                    or k in str(n.get("host", "")).lower()
                    or k == str(n.get("id"))]
        print("")
        line()
        info("面板节点浏览  共 %d 个%s" % (
            len(show), ("  (过滤: %s)" % kw) if kw else ""))
        line()
        if not show:
            info("没有匹配的节点")
        for n in show:
            flag = ""
            if n.get("parent_id"):
                flag += C_B + " [子]" + C_0
            if n.get("show") in (0, False):
                flag += C_Y + " [隐藏]" + C_0
            print("id=%-6s %-6s %-32s %s:%s%s" % (
                n.get("id"), TYPE_CN.get(n.get("type"), n.get("type")),
                str(n.get("name"))[:32], n.get("host"),
                n.get("server_port"), flag))
        print("")
        info("以上是面板全部节点, 已全量列出 (不再截断)")
        info("标签: [子]=复制出来的子节点   [隐藏]=面板设为不显示")
        print("")
        print(" 1) 按 id 修改 (名称/倍率/分组/显示)")
        print(" 2) 按 id 修改 SNI (VLESS 改 Reality, HY2 改证书域名)")
        print(" 3) 按 id 删除")
        print(" 4) 关键字过滤 (可搜 名称/地址/id, 留空清除)")
        print(" 0) 返回        直接回车也是返回")
        c = ask("选择", "")
        if not c or c == "0":
            return
        if c == "4":
            kw = ask("关键字 (留空清除过滤)", "")
        elif c in ("1", "2"):
            i = ask("节点 id", "")
            if not i.isdigit(): continue
            node = node_by_id(nodes, int(i))
            if not node:
                err("找不到 id=%s" % i); pause(); continue
            print("")
            info("%s  %s  %s:%s" % (node.get("name"), node.get("type"),
                                    node.get("host"), node.get("port")))
            try:
                done = edit_panel_fields(node) if c == "1" else edit_node_sni(node)
                if done:
                    nodes = get_nodes(); ctx["all_nodes"] = nodes
                    probe(ctx)
            except Exception as e:
                err("保存失败: %s" % e)
            pause()
        elif c == "3":
            i = ask("节点 id", "")
            if not i.isdigit(): continue
            node = node_by_id(nodes, int(i))
            if not node:
                err("找不到 id=%s" % i); pause(); continue
            local = [m["id"] for m in ctx.get("related", []) if m["in_conf"]]
            print("")
            warn("将删除面板节点 id=%s  %s" % (node.get("id"), node.get("name")))
            if int(i) in local:
                warn("注意: 这是本机 config.json 里的节点, 删了本机也会同步移除")
            if not confirm("确认删除", False):
                info("已取消"); continue
            try:
                drop_node(int(i))
                ok("已删除 id=%s" % i)
                if int(i) in local:
                    remove_from_conf(int(i))
                    restart_v2bx()
                nodes = get_nodes(); ctx["all_nodes"] = nodes
                probe(ctx)
            except Exception as e:
                err("删除失败: %s" % e)
            pause()
        else:
            err("没有这个选项: %s" % c); pause()

# ==================== 9) 修复模式 ====================
def repair(ctx):
    """config.json 丢了 / 乱了, 根据面板数据重建"""
    print("")
    line()
    info("修复模式: 根据面板上的节点重建本机 config.json")
    line()
    try:
        nodes = get_nodes()
    except Exception as e:
        err("读取面板失败: %s" % e); pause(); return
    ctx["all_nodes"] = nodes
    host = ctx.get("host") or ""
    code = ctx.get("code") or ""
    mine = []
    for n in nodes:
        if n.get("parent_id"):
            continue
        if n.get("type") not in CORE_TYPE:
            continue
        hit = False
        if host and str(n.get("host")) == str(host):
            hit = True
        if code:
            num, full = parse_code(n.get("name") or "")
            if full and full == code:
                hit = True
        if hit:
            mine.append(n)
    if not mine:
        warn("没找到属于本机的节点")
        info("匹配依据: 出口地址 %s / 编号 %s" % (host or "(无)", code or "(无)"))
        info("可以先用菜单 7 浏览面板确认节点名和地址")
        pause(); return
    print("")
    info("识别到属于本机的节点:")
    for n in mine:
        print("  id=%-6s %-6s %-30s %s:%s" % (
            n.get("id"), TYPE_CN.get(n.get("type"), n.get("type")),
            str(n.get("name"))[:30], n.get("host"), n.get("server_port")))
    print("")
    info("分割线节点(端口1)不会写入 config.json")
    real = [n for n in mine if int(n.get("server_port") or 0) > 1]
    skipped = len(mine) - len(real)
    if skipped:
        info("已跳过 %d 个分割线/占位节点" % skipped)
    if not real:
        warn("没有可写入的真实节点"); pause(); return
    if not confirm("用这 %d 个节点重建 config.json" % len(real), True):
        info("已取消"); return
    entries = []
    hops = []
    for n in real:
        ct = CORE_TYPE.get(n.get("type"))
        if not ct:
            continue
        entries.append(node_entry(n.get("id"), ct))
        if n.get("type") == "hysteria":
            m = re.match(r"^(\d+)\s*-\s*(\d+)$", str(n.get("port") or ""))
            if m:
                hops.append((int(m.group(1)), int(m.group(2)),
                             int(n.get("server_port"))))
    if not v2bx_installed():
        warn("V2bX 没装, 先安装")
        install_v2bx()
    ensure_cert()
    ensure_sing_origin()
    write_v2bx_conf(entries, replace_all=True)
    if hops:
        write_nft_hop(hops, hard=False)
    ensure_chrony()
    ensure_forward()
    run("systemctl enable V2bX >/dev/null 2>&1", check=False, timeout=30)
    restart_v2bx()
    if code:
        state_set(code=code, host=host)
    ok("修复完成, 共写入 %d 个节点" % len(entries))
    probe(ctx)

# ==================== 10) 卸载清理 ====================
def uninstall(ctx):
    print("")
    line()
    warn("卸载并清理本机")
    line()
    info("会做这些事:")
    info("  1. 停止并禁用 V2bX 服务")
    info("  2. 删除 /etc/V2bX  /etc/s-box  /usr/local/V2bX")
    info("  3. 清除 HY2 端口跳跃规则")
    info("面板上的节点默认保留, 下一步会单独问")
    info("配置文件 %s 也会一起删掉" % CONF_FILE)
    print("")
    if not confirm("确认卸载本机 V2bX", False):
        info("已取消"); return
    drop_panel = False
    rel = [r for r in (ctx.get("related") or []) if r["on_panel"]]
    if rel:
        print("")
        info("本机相关的面板节点:")
        for m in rel:
            extra = ""
            if m["kind"] == "分割线":
                extra = "  [分割线]"
            elif m["kind"] == "复制":
                extra = "  [子]"
            elif not m["in_conf"]:
                extra = "  [仅面板]"
            print("  id=%-6s %s%s" % (m["id"], m["name"], extra))
        drop_panel = confirm("要不要连面板上的这些节点一起删掉", False)
    print("")
    if drop_panel:
        # 先删子节点再删父节点, 避免面板残留孤儿
        order = sorted(rel, key=lambda x: 0 if x["kind"] == "复制" else 1)
        for m in order:
            try:
                drop_node(m["id"])
                ok("面板节点已删除 id=%s  %s" % (m["id"], m["name"]))
            except Exception as e:
                err("删除 id=%s 失败: %s" % (m["id"], e))
    run("systemctl stop V2bX", check=False, timeout=60)
    run("systemctl disable V2bX >/dev/null 2>&1", check=False, timeout=30)
    run("nft delete table ip hy2hop >/dev/null 2>&1", check=False, timeout=15)
    run("nft delete table ip6 hy2hop6 >/dev/null 2>&1", check=False, timeout=15)
    run("rm -f " + NFT_FILE, check=False, timeout=15)
    run("rm -rf /etc/V2bX /etc/s-box /usr/local/V2bX /usr/bin/V2bX "
        "/etc/systemd/system/V2bX.service", check=False, timeout=60)
    run("systemctl daemon-reload", check=False, timeout=30)
    ok("本机已清理干净")
    if not drop_panel and rel:
        print("")
        warn("面板上的节点还留着, 要删自己到面板处理")
    print("")
    ctx["code"] = ""
    ctx["code_guessed"] = False
    probe(ctx)
    pause()

def show_local(ctx):
    print("")
    line()
    rel = ctx.get("related") or []
    if not rel:
        info("本机没有检测到相关节点")
    for m in rel:
        tag = ""
        if m["kind"] == "分割线":
            tag = "  [分割线]"
        elif m["kind"] == "复制":
            tag = "  [子 parent=%s]" % m["parent_id"]
        elif not m["in_conf"]:
            tag = "  [仅面板]"
        print("id=%-6s %-6s %-28s 端口 %-16s%s" % (
            m["id"], TYPE_CN.get(m["type"], m["core_type"]),
            str(m["name"])[:28], fmt_port(m), tag))
    print("")
    info("匹配依据: config.json / 出口地址 %s / 编号 %s / 父子关系"
         % (ctx.get("host") or "(无)", ctx.get("code") or "(无)"))
    hops = load_hop_rules()
    if hops:
        print("")
        info("本机 HY2 跳跃规则:")
        for a, b, p in hops:
            info("  %d-%d -> %d" % (a, b, p))
    st = load_state()
    if st:
        print("")
        info("上次部署记录 (%s):" % time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(st.get("ts", 0))))
        if st.get("ports"):
            info("端口 " + json.dumps(st.get("ports"), ensure_ascii=False))
        if st.get("reality_public_key"):
            info("reality 公钥 " + str(st.get("reality_public_key")))
        if st.get("short_id"):
            info("short_id " + str(st.get("short_id")))
        if st.get("hops"):
            info("跳跃规则 " + json.dumps(st.get("hops")))
    print("")
    info("当前面板配置: %s" % PANEL_URL)
    info("配置文件: %s (token/apikey 已加密保存在里面)" % CONF_FILE)
    line()
    pause()

# ==================== 主菜单 ====================
def menu(ctx):
    while True:
        print_header(ctx)
        print("")
        print("-- 部署 --")
        print(" 1) 一键部署        分割线+VLESS+HY2+SS22")
        print(" 2) 新增 VLESS")
        print(" 3) 新增 HY2")
        print(" 4) 新增 SS22")
        print(" 5) 复制节点        订阅多一条一样的, 不动本机")
        print("")
        print("-- 管理 --")
        print(" 6) 本机*节点管理    看/删/改 本机相关节点")
        print(" 7) 面板节点浏览    全部节点, 可过滤")
        print(" 8) 查看本机信息")
        print("")
        print("-- 维护 --")
        print(" 9) 重启 V2bX")
        print("10) 修复模式        按面板数据重建 config.json")
        print("11) 重新设置机器编号")
        print("12) 卸载并清理本机")
        print("13) 重新配置面板参数")
        print("14) 新增分割线        只在面板建一条占位, 不动本机")
        print("")
        print("-- 系统 --")
        print("17) 转发环境检查/修复")
        print("18) 修改本机主机名")
        print(" 0) 退出")
        print("")
        c = ask("请选择", "")
        try:
            if c == "1":
                if ctx.get("local_ids"):
                    print("")
                    warn("本机已经有 %d 个节点了" % len(ctx["local_ids"]))
                    info("一键部署会重写 config.json, 已有节点会从本机配置里消失")
                    info("想加节点请用 2/3/4, 想复制请用 5")
                    if not confirm("仍然要一键部署", False):
                        continue
                if not ctx.get("host"):
                    ctx["host"] = choose_ip(ctx)
                ensure_code(ctx)
                deploy_all(ctx)
                probe(ctx)
                pause()
            elif c == "2":
                add_node(ctx, "vless"); probe(ctx); pause()
            elif c == "3":
                add_node(ctx, "hy2"); probe(ctx); pause()
            elif c == "4":
                add_node(ctx, "ss22"); probe(ctx); pause()
            elif c == "5":
                copy_node(ctx); probe(ctx); pause()
            elif c == "6":
                manage_local(ctx)
            elif c == "7":
                browse_panel(ctx)
            elif c == "8":
                show_local(ctx)
            elif c == "9":
                restart_v2bx(); pause()
            elif c == "10":
                repair(ctx); pause()
            elif c == "11":
                ensure_code(ctx, force=True)
                probe(ctx)
            elif c == "12":
                uninstall(ctx)
            elif c == "13":
                setup_config([], force=True)
                if test_panel():
                    probe(ctx)
                pause()
            elif c == "17":
                forward_status(ctx)
            elif c == "18":
                change_hostname(ctx)
            elif c == "14":
                add_separator(ctx); pause()
            elif c == "0":
                print("")
                return
        except SystemExit:
            raise
        except KeyboardInterrupt:
            print("")
            warn("已中断当前操作")
            pause()
        except Exception as e:
            print("")
            err("操作异常: %s" % e)
            pause()

def main():
    if os.geteuid() != 0:
        err("请用 root 运行")
        sys.exit(1)
    # v0.3 核心改动 3: 敏感信息全部由参数 / 配置文件 / 交互引导注入
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        print_usage()
        sys.exit(0)
    setup_config(argv)
    print("")
    info("正在验证面板连接 ...")
    while not test_panel():
        print("")
        err("面板连不上, 或者 token 不对")
        info("面板 %s" % PANEL_URL)
        info("路径 %s" % SECURE_PATH)
        info("token %s" % mask(ADMIN_TOKEN))
        if not confirm("要重新填面板参数吗", True):
            print("")
            err("没有可用的面板连接, 退出")
            sys.exit(1)
        setup_config([], force=True)
    ok("面板连接正常")
    ctx = {"hostname": socket.gethostname(), "code": "", "code_guessed": False}
    probe(ctx)
    print_header(ctx)
    if not ctx.get("host"):
        ctx["host"] = choose_ip(ctx)
    # v0.3 核心改动 2: 新机器进来直接问编号
    if ctx.get("is_new"):
        print("")
        warn("这是一台新机器 (本机没有 V2bX 节点配置)")
        info("先把机器编号定下来, 后面部署就不用再问了")
        info("直接回车可以跳过, 到选 1 部署时再问")
        # v0.4 核心改动 3: 去掉 y 确认, 直接进输入框
        got = ensure_code(ctx, force=True, allow_skip=True)
        if got:
            probe(ctx)
            print_header(ctx)
        else:
            print("")
            info("已跳过, 选 1 一键部署时会再问一次")
            pause()
    elif ctx.get("code"):
        print("")
        info("已识别为老机器, 编号 " + C_G + ctx["code"] + C_0)
        info("本机相关节点 %d 个, 上面已经全部列出" % len(ctx.get("related") or []))
        info("如果编号不对, 进菜单选 11 改")
        pause()
    else:
        print("")
        warn("本机有节点, 但节点名认不出编号")
        info("进菜单选 11 手动设置")
        pause()
    menu(ctx)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")
        print("已中断")
        sys.exit(130)
