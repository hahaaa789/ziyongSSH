#!/bin/bash
# 自用脚本，擅自使用后果自负
if [ -z "$BASH_VERSION" ]; then
  if command -v bash >/dev/null 2>&1; then exec bash "$0" "$@"; fi
  echo "未检测到 bash，尝试安装..."
  if command -v apk >/dev/null 2>&1; then apk add --no-cache bash && exec bash "$0" "$@"; fi
  echo "安装 bash 失败，请手动安装后重试"; exit 1
fi

PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkSf1uHPsLHRYVWPJ73yrEX5fU6FTIJEEwvBb4MD3Q7"
PUBKEY2="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1mSRnYvvYrv/ckppoC8q1KUiBAm3/FJk/H0jdOuGBM"
SSHDIR="/etc/ssh/sshd_config.d"
CONF="$SSHDIR/00-hardening.conf"
PORTCONF="$SSHDIR/01-port.conf"
AK="/root/.ssh/authorized_keys"
F2B="/etc/fail2ban/jail.d/00-sshd-custom.conf"
G="\033[32m"; R="\033[31m"; Y="\033[33m"; C="\033[36m"; N="\033[0m"

[ "$(id -u)" != "0" ] && { echo -e "${R}请用 root 运行${N}"; exit 1; }

OSID="unknown"; OSLIKE=""
[ -f /etc/os-release ] && . /etc/os-release && OSID="$ID" && OSLIKE="$ID_LIKE"

case "$OSID$OSLIKE" in
  *alpine*) FAMILY="alpine" ;;
  *debian*|*ubuntu*) FAMILY="debian" ;;
  *rhel*|*fedora*|*centos*) FAMILY="rhel" ;;
  *) FAMILY="unknown" ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  INIT="systemd"
elif command -v rc-service >/dev/null 2>&1; then
  INIT="openrc"
else
  INIT="unknown"
fi

if [ "$INIT" = "systemd" ]; then
  systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service' && SSHSVC="ssh" || SSHSVC="sshd"
else
  SSHSVC="sshd"
fi

pkg_install(){
  echo -e "${C}安装 $1 中...${N}"
  case "$FAMILY" in
    debian) apt-get update && apt-get install -y "$1" ;;
    alpine) apk add --no-cache "$1" ;;
    rhel)   command -v dnf >/dev/null && dnf install -y "$1" || yum install -y "$1" ;;
    *) echo -e "${R}未知系统，无法自动安装 $1${N}"; return 1 ;;
  esac
}
svc_restart(){ if [ "$INIT" = "openrc" ]; then rc-service "$1" restart; else systemctl restart "$1"; fi; }
svc_enable(){  if [ "$INIT" = "openrc" ]; then rc-update add "$1" default; rc-service "$1" start; else systemctl enable --now "$1"; fi; }
svc_disable(){ if [ "$INIT" = "openrc" ]; then rc-service "$1" stop; rc-update del "$1" default; else systemctl disable --now "$1"; fi; }
svc_active(){  if [ "$INIT" = "openrc" ]; then rc-service "$1" status >/dev/null 2>&1; else systemctl is-active --quiet "$1" 2>/dev/null; fi; }
port_used(){
  if command -v ss >/dev/null 2>&1; then ss -tln | grep -q ":$1 "
  else netstat -tln 2>/dev/null | grep -q ":$1 "; fi
}
set_hostname(){
  if command -v hostnamectl >/dev/null 2>&1; then hostnamectl set-hostname "$1"
  else echo "$1" > /etc/hostname; hostname "$1"; fi
}

mkdir -p "$SSHDIR"
if ! grep -qiE "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/" /etc/ssh/sshd_config; then
  echo -e "${Y}⚠ 主配置无 Include，已自动插入到首行${N}"
  sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config
fi
touch "$CONF"

cur_port(){ sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'; }
has_key(){  [ -f "$AK" ] && grep -qF "$PUBKEY"  "$AK"; }
has_key2(){ [ -f "$AK" ] && grep -qF "$PUBKEY2" "$AK"; }
pw_on(){ sshd -T 2>/dev/null | grep -q '^passwordauthentication yes'; }
f2b_on(){ svc_active fail2ban; }

purge(){
  for f in "$SSHDIR"/*.conf /etc/ssh/sshd_config; do
    [ "$f" = "$CONF" ] && continue
    [ "$f" = "$PORTCONF" ] && continue
    [ -f "$f" ] && sed -i -E "s/^[[:space:]]*($1[[:space:]].*)$/#\1/I" "$f"
  done
}
setc(){
  purge "$1"
  if grep -qiE "^[[:space:]]*$1[[:space:]]" "$CONF"; then
    sed -i -E "s|^[[:space:]]*$1[[:space:]].*|$1 $2|I" "$CONF"
  else
    echo "$1 $2" >> "$CONF"
  fi
}
apply(){
  cp "$CONF" /tmp/.hb.$$ 2>/dev/null
  cp "$PORTCONF" /tmp/.pb.$$ 2>/dev/null
  if sshd -t; then
    if svc_restart "$SSHSVC"; then
      echo -e "${G}✔ 已生效${N}"
    else
      echo -e "${R}✘ 重启 $SSHSVC 失败（配置已写入，服务未重载）${N}"
    fi
  else
    echo -e "${R}✘ sshd 配置校验失败，已回滚${N}"
    cp /tmp/.hb.$$ "$CONF" 2>/dev/null
    [ -f /tmp/.pb.$$ ] && cp /tmp/.pb.$$ "$PORTCONF" 2>/dev/null
  fi
  rm -f /tmp/.hb.$$ /tmp/.pb.$$
}

key_add(){
  if ! mkdir -p /root/.ssh 2>/tmp/.ke.$$; then
    echo -e "${R}✘ 无法创建 /root/.ssh 目录，报错：${N}"; cat /tmp/.ke.$$; rm -f /tmp/.ke.$$; return 1
  fi
  chmod 700 /root/.ssh
  if ! touch "$AK" 2>/tmp/.ke.$$; then
    echo -e "${R}✘ 无法创建 $AK ，报错：${N}"; cat /tmp/.ke.$$; rm -f /tmp/.ke.$$; return 1
  fi
  if ! has_key; then
    if ! echo "$PUBKEY" >> "$AK" 2>/tmp/.ke.$$; then
      echo -e "${R}✘ 写入公钥失败，报错：${N}"; cat /tmp/.ke.$$; rm -f /tmp/.ke.$$
      echo -e "${Y}  磁盘：$(df -h /root 2>&1 | tail -1)${N}"
      echo -e "${Y}  属性：$(lsattr "$AK" 2>&1)${N}"
      return 1
    fi
  fi
  rm -f /tmp/.ke.$$
  sed -i '/^$/d' "$AK"; chmod 600 "$AK"
  if ! has_key; then
    echo -e "${R}✘ 校验失败：公钥没有出现在 $AK 里${N}"
    echo -e "${Y}  脚本内 PUBKEY：${N}$PUBKEY"
    echo -e "${Y}  文件实际内容：${N}"; cat "$AK" 2>&1
    return 1
  fi
  setc PubkeyAuthentication yes
  echo -e "${G}✔ 公钥已注入并校验通过${N}"
  return 0
}
key_del(){
  if pw_on || has_key2; then
    grep -vF "$PUBKEY" "$AK" > "$AK.t" 2>/dev/null && mv "$AK.t" "$AK" && chmod 600 "$AK"
    echo -e "${Y}✔ 公钥已撤销${N}"
  else
    echo -e "${R}✘ 拒绝：密码登录已关闭且无备用公钥，撤销公钥会导致无法登录${N}"
  fi
}

key2_add(){
  if ! mkdir -p /root/.ssh 2>/tmp/.k2.$$; then
    echo -e "${R}✘ 无法创建 /root/.ssh 目录，报错：${N}"; cat /tmp/.k2.$$; rm -f /tmp/.k2.$$; return 1
  fi
  chmod 700 /root/.ssh
  if ! touch "$AK" 2>/tmp/.k2.$$; then
    echo -e "${R}✘ 无法创建 $AK ，报错：${N}"; cat /tmp/.k2.$$; rm -f /tmp/.k2.$$; return 1
  fi
  if ! has_key2; then
    if ! echo "$PUBKEY2" >> "$AK" 2>/tmp/.k2.$$; then
      echo -e "${R}✘ 写入备用公钥失败，报错：${N}"; cat /tmp/.k2.$$; rm -f /tmp/.k2.$$
      echo -e "${Y}  磁盘：$(df -h /root 2>&1 | tail -1)${N}"
      echo -e "${Y}  属性：$(lsattr "$AK" 2>&1)${N}"
      return 1
    fi
  fi
  rm -f /tmp/.k2.$$
  sed -i '/^$/d' "$AK"; chmod 600 "$AK"
  if ! has_key2; then
    echo -e "${R}✘ 校验失败：备用公钥没有出现在 $AK 里${N}"
    echo -e "${Y}  脚本内 PUBKEY2：${N}$PUBKEY2"
    echo -e "${Y}  文件实际内容：${N}"; cat "$AK" 2>&1
    return 1
  fi
  setc PubkeyAuthentication yes
  echo -e "${G}✔ 备用公钥已注入并校验通过（与主公钥共存，两把都能登）${N}"
  return 0
}
key2_del(){
  if has_key || pw_on; then
    grep -vF "$PUBKEY2" "$AK" > "$AK.t2" 2>/dev/null && mv "$AK.t2" "$AK" && chmod 600 "$AK"
    if has_key2; then
      echo -e "${R}✘ 撤销失败，$AK 中仍存在备用公钥${N}"; return 1
    fi
    echo -e "${Y}✔ 备用公钥已撤销（主公钥保留）${N}"
  else
    echo -e "${R}✘ 拒绝：主公钥不存在且密码登录已关闭，撤销备用公钥会导致无法登录${N}"
    return 1
  fi
}

f2b_logpath(){
  if [ "$INIT" = "systemd" ]; then echo "systemd"
  elif [ -f /var/log/auth.log ]; then echo "/var/log/auth.log"
  elif [ -f /var/log/secure ]; then echo "/var/log/secure"
  elif [ -f /var/log/messages ]; then echo "/var/log/messages"
  else echo "none"; fi
}
f2b_add(){
  command -v fail2ban-server >/dev/null 2>&1 || pkg_install fail2ban || return 1
  mkdir -p /etc/fail2ban/jail.d
  local lp; lp=$(f2b_logpath)
  local BACKLINE
  if [ "$lp" = "systemd" ]; then
    BACKLINE="backend  = systemd"
  elif [ "$lp" = "none" ]; then
    echo -e "${R}✘ 找不到 SSH 日志文件，fail2ban 无法工作${N}"
    echo -e "${Y}  请先启用 syslog（Alpine: apk add busybox-openrc && rc-service syslog start）${N}"
    return 1
  else
    BACKLINE="backend  = auto
logpath  = $lp"
  fi
  cat > "$F2B" << F2BEOF
[sshd]
enabled  = true
port     = $(cur_port)
$BACKLINE
maxretry = 5
findtime = 60
bantime  = 60
F2BEOF
  svc_enable fail2ban
  svc_restart fail2ban
  sleep 1
  if f2b_on; then
    echo -e "${G}✔ 防爆破已开启（60秒5次失败封禁1分钟）${N}"
  else
    echo -e "${R}✘ fail2ban 启动失败，错误如下：${N}"
    if [ "$INIT" = "systemd" ]; then journalctl -u fail2ban -n 20 --no-pager
    else tail -20 /var/log/fail2ban.log 2>/dev/null || echo "无日志"; fi
    return 1
  fi
}
f2b_del(){ svc_disable fail2ban; rm -f "$F2B"; echo -e "${Y}✔ 防爆破已关闭${N}"; }

keyonly_on(){
  if ! key_add; then
    echo -e "${R}✘ 已中止：公钥注入失败，不会关闭密码登录${N}"
    echo -e "${Y}  当前登录方式保持不变，不存在锁死风险${N}"
    return 1
  fi
  setc PasswordAuthentication no
  setc PermitRootLogin prohibit-password
  apply
  if sshd -T 2>/dev/null | grep -q '^pubkeyauthentication yes'; then
    echo -e "${G}已切换为仅密钥登录${N}"
  else
    echo -e "${R}✘ 危险：生效配置里 PubkeyAuthentication 不是 yes，正在回滚密码登录${N}"
    setc PasswordAuthentication yes; setc PermitRootLogin yes; apply
  fi
}
keyonly_off(){
  setc PasswordAuthentication yes
  setc PermitRootLogin yes
  apply
  echo -e "${Y}密码登录已恢复，公钥保留${N}"
}

set_port(){
  read -rp "  新端口 (1-65535): " p
  if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo -e "${R}端口非法${N}"; return 1
  fi
  if [ "$p" != "$(cur_port)" ] && port_used "$p"; then
    echo -e "${R}端口 $p 已被占用${N}"; return 1
  fi
  purge Port
  echo "Port $p" > "$PORTCONF"
  apply
  if [ -f "$F2B" ]; then
    sed -i "s/^port .*/port     = $p/" "$F2B"
    svc_restart fail2ban
  fi
  echo -e "${Y}⚠ 请确认 VPS 厂商安全组已放行 $p${N}"
  echo -e "${Y}⚠ 勿关闭当前窗口，另开窗口测试成功后再关${N}"
}

status(){
clear
echo -e "${R}  自用脚本，擅自使用后果自负${N}"
echo "  ═══════════════════════════════════════════"
has_key  && echo -e "   公钥注入    : ${G}✅ 已部署${N}" || echo -e "   公钥注入    : ${R}❌ 未部署${N}"
has_key2 && echo -e "   备用公钥    : ${G}✅ 已部署${N}" || echo -e "   备用公钥    : ${R}❌ 未部署${N}"
f2b_on   && echo -e "   防爆破      : ${G}✅ 已开启${N} (60s/5次封1分钟)" || echo -e "   防爆破      : ${R}❌ 未开启${N}"
pw_on    && echo -e "   仅密钥登录  : ${R}❌ 密码登录开启中${N}" || echo -e "   仅密钥登录  : ${G}✅ 已开启${N}"
echo -e "   SSH 端口    : ${C}$(cur_port)${N}"
echo -e "   主机名      : ${C}$(hostname)${N}"
echo -e "   系统        : ${C}$OSID${N} / ${C}$FAMILY${N} / ${C}$INIT${N}"
echo "  ═══════════════════════════════════════════"
echo "   1、默认全开（注入公钥+防爆破+仅密钥登录）"
echo "   2、注入公钥          （再次执行则关闭）"
echo "   3、开启防爆破 60s/5次（再次执行则关闭）"
echo "   4、仅密钥登录        （再次执行则关闭）"
echo "   5、修改 SSH 端口"
echo "   6、修改主机名"
echo "   7、修改 root 密码"
echo "   9、注入备用公钥      （再次执行则撤销）"
echo "   0、退出"
echo "  ═══════════════════════════════════════════"
[ "$FAMILY" = "unknown" ] && echo -e "${Y}  ⚠ 未识别的系统，功能可能不完整${N}"
}

run_op(){
  case "$1" in
    1) if key_add; then
         f2b_add || echo -e "${Y}⚠ 防爆破配置失败（不影响登录），继续${N}"
         setc PasswordAuthentication no
         setc PermitRootLogin prohibit-password
         apply
         if sshd -T 2>/dev/null | grep -q '^pubkeyauthentication yes'; then
           echo -e "${G}✔ 全部完成${N}"
         else
           echo -e "${R}✘ 危险：生效配置里 PubkeyAuthentication 不是 yes，正在回滚密码登录${N}"
           setc PasswordAuthentication yes; setc PermitRootLogin yes; apply
         fi
       else
         echo -e "${R}✘ 已中止：公钥注入失败，已跳过「关闭密码登录」${N}"
         echo -e "${Y}  密码登录保持可用，不会锁死，请按上方报错排查后重试${N}"
         return 1
       fi ;;
    2) if has_key; then key_del; else key_add && apply; fi ;;
    3) if f2b_on; then f2b_del; else f2b_add; fi ;;
    4) if pw_on; then keyonly_on; else keyonly_off; fi ;;
    5) set_port ;;
    6) read -rp "  新主机名: " h
       if [ -n "$h" ]; then
         set_hostname "$h"
         sed -i "s/^127.0.1.1.*/127.0.1.1\t$h/" /etc/hosts 2>/dev/null
         grep -q "^127.0.1.1" /etc/hosts || printf "127.0.1.1\t%s\n" "$h" >> /etc/hosts
         echo -e "${G}✔ 已改为 $h${N}"
       fi ;;
    7) passwd root ;;
    9) if has_key2; then key2_del; else key2_add && apply; fi ;;
    0) exit 0 ;;
    *) echo -e "${R}无效选项${N}"; return 1 ;;
  esac
}

# ── 参数模式：带参数直接执行后退出 ──
if [ -n "$1" ]; then
  echo -e "${C}非交互模式，执行选项 $1${N}"
  run_op "$1"; rc=$?
  echo -e "${C}══ 执行完毕，当前状态 ══${N}"
  has_key  && echo -e "   公钥注入    : ${G}✅ 已部署${N}" || echo -e "   公钥注入    : ${R}❌ 未部署${N}"
  has_key2 && echo -e "   备用公钥    : ${G}✅ 已部署${N}" || echo -e "   备用公钥    : ${R}❌ 未部署${N}"
  f2b_on   && echo -e "   防爆破      : ${G}✅ 已开启${N}" || echo -e "   防爆破      : ${R}❌ 未开启${N}"
  pw_on    && echo -e "   仅密钥登录  : ${R}❌ 密码登录开启中${N}" || echo -e "   仅密钥登录  : ${G}✅ 已开启${N}"
  echo -e "   SSH 端口    : ${C}$(cur_port)${N}"
  exit $rc
fi

while true; do
  status
  read -rp "  请选择 [回车=1]: " op
  op=${op:-1}
  run_op "$op"
  read -rp "  回车继续..." _
done
