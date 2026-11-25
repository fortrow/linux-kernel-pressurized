#!/bin/sh
set -eu

export PATH=/mnt/host:/usr/sbin:/usr/bin:/sbin:/bin

echo "=================================================================="
echo " PRESSURE + SFW + PRESSURE-AUTHD END-TO-END VERIFICATION SUITE"
echo "=================================================================="

# 0. Verify Netfilter is compiled out and Pressure LSM is active
echo "[0] Checking kernel LSM list and Netfilter removal..."
cat /sys/kernel/security/lsm | grep -q "pressure"
if [ -d /proc/sys/net/netfilter ]; then
    echo "FAIL: Netfilter still present!"
    exit 1
fi
echo "PASS: Active LSMs = $(cat /sys/kernel/security/lsm) (Netfilter removed)"

# Create test /dev nodes for keyboard/mouse, uinput, storage, and tty1 if absent in minimal VM
mkdir -p /dev/input
[ -e /dev/input/event0 ] || mknod /dev/input/event0 c 13 64
[ -e /dev/uinput ]       || mknod /dev/uinput c 10 223
[ -e /dev/sr0 ]          || mknod /dev/sr0 b 11 0
[ -e /dev/tty1 ]         || mknod /dev/tty1 c 4 1
[ -e /dev/tty2 ]         || mknod /dev/tty2 c 4 2
[ -e /dev/tty3 ]         || mknod /dev/tty3 c 4 3
chmod 0666 /dev/input/event0 /dev/uinput /dev/sr0 /dev/tty1 /dev/tty2 /dev/tty3 /dev/ttyS0 2>/dev/null || true

# Bring up dual-stack loopback interface for sfw worker
IP=/usr/sbin/ip
$IP link set lo up 2>/dev/null || ifconfig lo 127.0.0.1 up
$IP -6 addr add ::1/128 dev lo nodad 2>/dev/null || true

# Seed EL10-style packaged distro accounts/groups (preserving any already in image)
echo "[0b] Seeding/capturing preexisting EL10-style distro accounts & group memberships..."
[ -f /etc/passwd ] || printf 'root:x:0:0:root:/root:/bin/sh\n' > /etc/passwd
[ -f /etc/group ]  || printf 'root:x:0:\n' > /etc/group
[ -f /etc/shadow ] || printf 'root:!:19000:0:99999:7:::\n' > /etc/shadow
grep -q '^sshd:' /etc/passwd || printf 'sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin\n' >> /etc/passwd
grep -q '^nginx:' /etc/passwd || printf 'nginx:x:992:990:Nginx web server:/var/lib/nginx:/sbin/nologin\n' >> /etc/passwd
grep -q '^el10-chrony:' /etc/passwd || printf 'el10-chrony:x:995:992:chrony daemon:/var/lib/chrony:/sbin/nologin\n' >> /etc/passwd
grep -q '^wheel:' /etc/group || printf 'wheel:x:10:root,ops\n' >> /etc/group
grep -q '^sshd:' /etc/group || printf 'sshd:x:74:\n' >> /etc/group
grep -q '^nginx:' /etc/group || printf 'nginx:x:990:sshd\n' >> /etc/group
grep -q '^el10-journal:' /etc/group || printf 'el10-journal:x:190:sshd,nginx\n' >> /etc/group
grep -q '^sshd:' /etc/shadow || printf 'sshd:!!:19000::::::\n' >> /etc/shadow
grep -q '^nginx:' /etc/shadow || printf 'nginx:!!:19000::::::\n' >> /etc/shadow
grep -q '^el10-chrony:' /etc/shadow || printf 'el10-chrony:!!:19000::::::\n' >> /etc/shadow
chmod 0000 /etc/shadow

ORIG_SSHD_PW=$(grep '^sshd:' /etc/passwd)
ORIG_SSHD_UID=$(awk -F: '/^sshd:/ {print $3}' /etc/passwd)
ORIG_NGINX_PW=$(grep '^nginx:' /etc/passwd)
ORIG_NGINX_UID=$(awk -F: '/^nginx:/ {print $3}' /etc/passwd)
ORIG_CHRONY_PW=$(grep '^el10-chrony:' /etc/passwd)
ORIG_WHEEL_GR=$(grep '^wheel:' /etc/group)
ORIG_JOURNAL_GR=$(grep '^el10-journal:' /etc/group)
ORIG_SSHD_SH=$(grep '^sshd:' /etc/shadow)

# 1. Initialize press runtime dirs, load sfw.ko kernel worker, start pressure-authd (permissive first-boot!)
echo "[1] Starting sfw.ko kernel worker and pressure-authd in permissive boot stage..."
press boot-init
insmod /mnt/host/sfw.ko
sleep 1
[ -S /run/pressure/sfw/mux.sock ]
pressure-authd --daemon
sleep 1
sure status

# 1a. Verify first-boot EL10 distro-account coexistence (zero clobbering, zero Pressure credentials granted)
echo "[1a] Verifying first-boot EL10 distro-account coexistence..."
grep -Fqx "$ORIG_SSHD_PW" /etc/passwd
grep -Fqx "$ORIG_NGINX_PW" /etc/passwd
grep -Fqx "$ORIG_CHRONY_PW" /etc/passwd
grep -Fqx "$ORIG_WHEEL_GR" /etc/group
grep -Fqx "$ORIG_JOURNAL_GR" /etc/group
grep -Fqx "$ORIG_SSHD_SH" /etc/shadow
case "$(stat -c %a /etc/shadow)" in
    0|000|0000) ;;
    *) echo "FAIL: /etc/shadow permissions altered on first boot: $(stat -c %a /etc/shadow)"; exit 1 ;;
esac
if grep -q "pub_uid=${ORIG_SSHD_UID} " /sys/kernel/security/pressure/users || \
   grep -q "pub_uid=${ORIG_NGINX_UID} " /sys/kernel/security/pressure/users; then
    echo "FAIL: preexisting distro account unexpectedly registered in kernel Pressure user table!"
    exit 1
fi
echo "PASS: First-boot EL10 distro accounts, group memberships, /etc/shadow mode 0000, and non-registration verified"

# 1b. Validate declarative policy parser ('sure check' on valid & invalid .pr files) & default-deny AF_UNIX
echo "[1b] Testing 'sure check' declarative policy validator, pre-policy 'sure ready' gate & default-deny AF_UNIX..."
if sure ready --require-sfw 2>/dev/null; then
    echo "FAIL: sure ready --require-sfw should NOT return ready before policy is loaded!"
    exit 1
fi
sure check /mnt/host/policies/server.pr
cat > /tmp/bad_syntax.pr <<'EOF'
define $BAD = 999.999.999.999/99;
sfw_socket allow connect uid 0 dst $BAD ports 80 dev * max_prov auth_local;
EOF
if sure check /tmp/bad_syntax.pr 2>/dev/null; then
    echo "FAIL: sure check accepted malformed CIDR!"
    exit 1
fi
cat > /tmp/bad_unix.pr <<'EOF'
unix_socket allow subject subj:foo type stream ops { connect } endpoint - max_prov auth_local;
EOF
if sure check /tmp/bad_unix.pr 2>/dev/null; then
    echo "FAIL: sure check accepted endpoint op with '-' endpoint!"
    exit 1
fi
rm -f /tmp/bad_syntax.pr /tmp/bad_unix.pr

# Verify default-deny AF_UNIX creation when enforce=1 and unix_rules is empty
press enforce on
pressure_e2e_test unix-deny-create

# Load explicit AF_UNIX service & supervisor policy (before dependent services & IPC run under enforce=1)
cat > /tmp/test_base_unix.pr <<'EOF'
unix_socket flush;
unix_socket allow subject subj:boot type stream ops { create, connect, send, recv } endpoint /run/pressure/authd.sock peer subj:pressure_authd max_prov auth_local;
unix_socket allow subject subj:boot type stream ops { create, connect, send, recv } endpoint /run/pressure/sfw/mux.sock peer subj:sfw_worker max_prov auth_local;
unix_socket allow subject subj:boot type stream ops { create, connect, send, recv } endpoint /run/php-fpm/www.sock peer subj:daemon_phpfpm max_prov auth_local;
unix_socket allow subject subj:pressure_authd type stream ops { create, bind, send, recv } endpoint /run/pressure/authd.sock peer * max_prov auth_local;
unix_socket allow subject * type stream ops { pass_fd, send, recv } endpoint /run/systemd/journal/stdout peer subj:boot max_prov remote;
unix_socket allow subject subj:user_* type stream ops { create, connect, send, recv } endpoint /run/pressure/sfw/mux.sock peer subj:sfw_worker max_prov auth_local;
unix_socket allow subject subj:daemon_webd type stream ops { create, connect, send, recv } endpoint /run/pressure/sfw/mux.sock peer subj:sfw_worker max_prov remote;
unix_socket allow subject subj:daemon_nginx type stream ops { create, connect, send, recv } endpoint /run/pressure/sfw/mux.sock peer subj:sfw_worker max_prov remote;
unix_socket allow subject subj:daemon_phpfpm type stream ops { create, bind, send, recv } endpoint /run/php-fpm/www.sock peer * max_prov remote;
unix_socket allow subject subj:daemon_phpfpm type stream ops { create, bind, send, recv } endpoint @unix_test_abs peer * max_prov remote;
unix_socket allow subject subj:daemon_phpfpm type dgram ops { create, bind, recv } endpoint /run/dgram/test.sock peer * max_prov remote;
unix_socket allow subject subj:daemon_phpfpm type dgram ops { create, bind, recv } endpoint @unix_dgram_abs peer * max_prov remote;
unix_socket allow subject subj:daemon_nginx type stream ops { create, connect, send, recv } endpoint /run/php-fpm/www.sock peer subj:daemon_phpfpm max_prov remote;
unix_socket allow subject subj:daemon_nginx type stream ops { create, connect, send, recv } endpoint /run/ipc/carrier.sock peer subj:daemon_unauth_recv max_prov remote;
unix_socket allow subject subj:daemon_nginx type dgram ops { create, send } endpoint /run/dgram/test.sock peer subj:daemon_phpfpm max_prov remote;
unix_socket allow subject subj:daemon_nginx type dgram ops { create, send } endpoint @unix_dgram_abs peer subj:daemon_phpfpm max_prov remote;
unix_socket allow subject subj:daemon_probe type any ops { create } endpoint - max_prov remote;
unix_socket allow subject subj:daemon_unauth_recv type stream ops { create, bind, recv } endpoint /run/ipc/carrier.sock peer * max_prov remote;
set enforce on;
EOF
sure check /tmp/test_base_unix.pr
sure load /tmp/test_base_unix.pr
echo "PASS: sure check validated all 4 profiles, rejected invalid syntax, verified default-deny AF_UNIX, and loaded explicit service rules"

# 2. Test Pre-Login Dual-Stack (IPv4 + IPv6 + UDP + poll + LD_PRELOAD shim) Localhost via root AF_UNIX sfw worker!
echo "[2] Testing PRELOGIN stage IPv4, IPv6 & UDP/poll localhost over root-owned AF_UNIX sfw worker..."
sure status | grep -q "stage:            PRELOGIN"
pressure_e2e_test sfw-loopback 19080 check-raw
pressure_e2e_test sfw-loopback6 19086 check-raw
LD_PRELOAD=/lib/x86_64-linux-gnu/libpressureshim.so pressure_e2e_test shim-loopback6 19087
LD_PRELOAD=/lib/x86_64-linux-gnu/libpressureshim.so pressure_e2e_test shim-udp-poll 19053

# 2b. Test Live Runtime sfw 5-Chain FORWARD + Stateful MASQUERADE + DNAT Port-Forwarding!
echo "[2b] Testing live runtime sfw FORWARD chain, MASQUERADE, and DNAT port-forwarding..."
IP=/usr/sbin/ip
mkdir -p /var/run/netns
echo 1 > /proc/sys/net/ipv4/ip_forward
$IP netns add lan_ns
$IP netns add wan_ns
$IP link add veth-lan type veth peer name eth-lan
$IP link set eth-lan netns lan_ns
$IP link add veth-wan type veth peer name eth-wan
$IP link set eth-wan netns wan_ns

$IP addr add 10.10.1.1/24 dev veth-lan
$IP link set veth-lan up
$IP addr add 192.0.2.1/24 dev veth-wan
$IP link set veth-wan up

$IP netns exec lan_ns $IP link set lo up
$IP netns exec lan_ns $IP addr add 10.10.1.2/24 dev eth-lan
$IP netns exec lan_ns $IP link set eth-lan up
$IP netns exec lan_ns $IP route add default via 10.10.1.1

$IP netns exec wan_ns $IP link set lo up
$IP netns exec wan_ns $IP addr add 192.0.2.2/24 dev eth-wan
$IP netns exec wan_ns $IP link set eth-wan up
# Notice wan_ns has NO route to 10.10.1.0/24! Traffic ONLY succeeds if sfw MASQUERADEs to 192.0.2.1!

# Verify sfw FORWARD chain initializes to DROP out-of-the-box (fail-closed!) before any policy is loaded!
grep -q "forward=DROP" /proc/pressure_sfw/chains
$IP netns exec wan_ns pressure_e2e_test netns-server 192.0.2.2 8085 192.0.2.1 &
WAN_SRV=$!
sleep 1
if $IP netns exec lan_ns pressure_e2e_test netns-client 192.0.2.2 8085 "ACK" 2>/dev/null; then
    echo "FAIL: sfw forward drop policy did not block unapproved forwarded traffic!"
    exit 1
fi
echo "PASS: sfw FORWARD default DROP blocked unapproved routed traffic"

# Live-enable sfw MASQUERADE + stateful FORWARD rules (outbound tcp/8085 + established return)
sfw nat add masquerade veth-wan 10.10.1.0/24
sfw chain add forward allow tcp veth-lan veth-wan 10.10.1.0/24 192.0.2.0/24 8085 8085 new
sfw chain add forward allow tcp veth-lan veth-wan 10.10.1.0/24 192.0.2.0/24 8085 8085 established
sfw chain add forward allow tcp veth-wan veth-lan 192.0.2.0/24 10.10.1.0/24 0 65535 established

$IP netns exec lan_ns pressure_e2e_test netns-client 192.0.2.2 8085 "ACK_FROM_192.0.2.2_TO_192.0.2.1"
wait "$WAN_SRV"
echo "PASS: Live sfw POSTROUTING MASQUERADE (10.10.1.2 -> 192.0.2.1) + PREROUTING reverse-NAT verified!"

# Live-enable sfw PREROUTING DNAT port-forwarding: WAN -> 192.0.2.1:8088 forwarded to LAN 10.10.1.2:9090!
sfw nat add dnat tcp veth-wan 192.0.2.1/32 8088 10.10.1.2 9090
sfw chain add forward allow tcp veth-wan veth-lan 192.0.2.0/24 10.10.1.2/32 9090 9090 any
sfw chain add forward allow tcp veth-lan veth-wan 10.10.1.2/32 192.0.2.0/24 0 65535 established

$IP netns exec lan_ns pressure_e2e_test netns-server 10.10.1.2 9090 192.0.2.2 &
LAN_SRV=$!
sleep 1
$IP netns exec wan_ns pressure_e2e_test netns-client 192.0.2.1 8088 "ACK_FROM_10.10.1.2_TO_192.0.2.2"
wait "$LAN_SRV"
echo "PASS: Live sfw PREROUTING DNAT port-forward (192.0.2.1:8088 -> 10.10.1.2:9090) verified!"

# 2c. Test Live IPv6 FORWARD + NAT66 MASQUERADE + NAT66 DNAT loaded declaratively via 'sure load'!
echo "[2c] Testing live IPv6 FORWARD + NAT66 (MASQUERADE & DNAT) via 'sure load'..."
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
$IP -6 addr add fd00:10::1/64 dev veth-lan nodad
$IP -6 addr add fd00:20::1/64 dev veth-wan nodad
$IP netns exec lan_ns $IP -6 addr add fd00:10::2/64 dev eth-lan nodad
$IP netns exec lan_ns $IP -6 route add default via fd00:10::1
$IP netns exec wan_ns $IP -6 addr add fd00:20::2/64 dev eth-wan nodad
# Notice wan_ns has NO IPv6 route to fd00:10::/64! Return packets ONLY arrive if NAT66 MASQUERADE works!

# Verify unapproved IPv6 forwarding is blocked by FORWARD default DROP (while NDP neighbor discovery works!)
$IP netns exec wan_ns pressure_e2e_test netns-server6 fd00:20::2 8086 fd00:20::1 &
WAN6_SRV=$!
sleep 1
if $IP netns exec lan_ns pressure_e2e_test netns-client6 fd00:20::2 8086 "ACK6" 2>/dev/null; then
    echo "FAIL: sfw IPv6 forward drop policy did not block unapproved IPv6 forwarded traffic!"
    exit 1
fi
echo "PASS: sfw IPv6 FORWARD default DROP blocked unapproved IPv6 routed traffic"

# Write a live declarative .pr policy snippet and load it via 'sure load'!
cat > /tmp/live_ipv6_nat.pr <<'EOF'
define $LAN6    = fd00:10::/64;
define $WAN6    = fd00:20::/64;
define $WAN6_GW = fd00:20::1/128;

netdev veth-lan label dev:net_lan class net_ext origin remote;
netdev veth-wan label dev:net_wan class net_ext origin remote;

# Allow outbound IPv6 tcp/8086 + established return, and MASQUERADE LAN6 -> veth-wan!
sfw_chain allow forward proto tcp in veth-lan out veth-wan src $LAN6 dst $WAN6 dports 8086 state new;
sfw_chain allow forward proto tcp in veth-lan out veth-wan src $LAN6 dst $WAN6 dports 8086 state established;
sfw_chain allow forward proto tcp in veth-wan out veth-lan src $WAN6 dst $LAN6 dports 0-65535 state established;
sfw_nat masquerade out veth-wan src $LAN6;

# Port-forward WAN6 [fd00:20::1]:8089 -> LAN6 [fd00:10::2]:9091!
sfw_nat dnat proto tcp in veth-wan dst $WAN6_GW dport 8089 to [fd00:10::2]:9091;
sfw_chain allow forward proto tcp in veth-wan out veth-lan src $WAN6 dst fd00:10::2/128 dports 9091 state any;
sfw_chain allow forward proto tcp in veth-lan out veth-wan src fd00:10::2/128 dst $WAN6 dports 0-65535 state established;
EOF

sure check /tmp/live_ipv6_nat.pr
sure load /tmp/live_ipv6_nat.pr
sure ready --require-sfw

# Verify transactional 'sure load' rollback: a failing policy that flushes chains/NAT must leave active rules intact!
cat > /tmp/rollback_test.pr <<'EOF'
sfw_chain flush;
sfw_nat flush;
device /dev/missing_quadtap99 label dev:quadtap class other_chr origin remote max_sessions 1;
EOF
if sure load /tmp/rollback_test.pr 2>/dev/null; then
    echo "FAIL: sure load succeeded on missing required device!"
    exit 1
fi
# Also test kernel-level mid-transaction abort after live flushes!
echo "begin" > /proc/pressure_sfw/txn
echo "flush" > /proc/pressure_sfw/chains
echo "flush" > /proc/pressure_sfw/nat
echo "abort" > /proc/pressure_sfw/txn
grep -q "dst=fd00:20::/64" /proc/pressure_sfw/chains
grep -q "MASQUERADE" /proc/pressure_sfw/nat

# Test concurrent loader (-EBUSY): required txn begin failure MUST stop before policy edits!
cat > /tmp/concurrent_flush.pr <<'EOF'
sfw_chain flush;
sfw_nat flush;
set enforce on;
EOF
/bin/sh -c 'echo begin > /proc/pressure_sfw/txn; sleep 2; echo abort > /proc/pressure_sfw/txn' &
CONC_PID=$!
sleep 1
if sure load /tmp/concurrent_flush.pr 2>/dev/null; then
    echo "FAIL: concurrent sure load should have been rejected with EBUSY!"
    exit 1
fi
grep -q "dst=fd00:20::/64" /proc/pressure_sfw/chains
grep -q "MASQUERADE" /proc/pressure_sfw/nat
wait "$CONC_PID"

# Test crashed loader (SIGKILL mid-transaction): sure ready stays closed, next sure load auto-recovers!
/bin/sh -c 'echo begin > /sys/kernel/security/pressure/txn; kill -9 $$' || true
if sure ready --require-sfw 2>/dev/null; then
    echo "FAIL: sure ready should be NOT READY while crashed txn_active=1!"
    exit 1
fi

# Test degraded latch (partial commit / failed rollback protection): blocks sure ready until clean reload!
echo "abort" > /sys/kernel/security/pressure/txn 2>/dev/null || true
echo "mark_degraded" > /sys/kernel/security/pressure/txn
if sure ready --require-sfw 2>/dev/null; then
    echo "FAIL: sure ready should be NOT READY when txn_degraded=1!"
    exit 1
fi
cat > /tmp/clear_degraded.pr <<'EOF'
set enforce on;
EOF
sure load /tmp/clear_degraded.pr
sure ready --require-sfw
echo "PASS: Transactional reload rollback, concurrent EBUSY guard, crashed-loader recovery, and txn_degraded latch verified!"

$IP netns exec lan_ns pressure_e2e_test netns-client6 fd00:20::2 8086 "ACK6_FROM_[fd00:20::2]_TO_[fd00:20::1]"
wait "$WAN6_SRV"
echo "PASS: Live IPv6 NAT66 MASQUERADE (fd00:10::2 -> fd00:20::1) verified!"

$IP netns exec lan_ns pressure_e2e_test netns-server6 fd00:10::2 9091 fd00:20::2 &
LAN6_SRV=$!
sleep 1
$IP netns exec wan_ns pressure_e2e_test netns-client6 fd00:20::1 8089 "ACK6_FROM_[fd00:10::2]_TO_[fd00:20::2]"
wait "$LAN6_SRV"
echo "PASS: Live IPv6 NAT66 DNAT port-forward ([fd00:20::1]:8089 -> [fd00:10::2]:9091) verified!"

sfw list
sfw conntrack
sfw stats

# 3. Provision multi-user family accounts (alice, bob) and daemons (webd, dbd, pariwall) via pressure-authd
echo "[3] Verifying EL10 collision guards & provisioning Pressure users/daemons with random UIDs..."
if pressure-authctl useradd sshd "TryHijack!2026" 2>/dev/null; then
    echo "FAIL: useradd allowed colliding with preexisting distro user 'sshd'!"
    exit 1
fi
if pressure-authctl useradd --daemon nginx - 2>/dev/null; then
    echo "FAIL: useradd --daemon allowed colliding with preexisting distro user 'nginx'!"
    exit 1
fi
if pressure-authctl useradd --daemon wheel - 2>/dev/null; then
    echo "FAIL: useradd --daemon allowed colliding with preexisting distro group 'wheel'!"
    exit 1
fi
echo "PASS: Name collisions with distro users ('sshd', 'nginx') and distro group ('wheel') cleanly rejected"

pressure-authctl useradd alice "AliceStrongPass!2026"
pressure-authctl useradd bob   "BobStrongPass!2026"
pressure-authctl useradd --daemon webd -
pressure-authctl useradd --daemon dbd  -
pressure-authctl useradd --daemon pariwall - --label subj:daemon_pariwall

echo "--- /etc/passwd (POSIX compatibility with preserved EL10 accounts + random Pressure pub_uid) ---"
cat /etc/passwd
echo "--- /etc/shadow (Preserved EL10 entries + locked '!' Pressure vault entries) ---"
cat /etc/shadow

ALICE_UID=$(awk -F: '/^alice:/ {print $3}' /etc/passwd)
BOB_UID=$(awk -F: '/^bob:/ {print $3}' /etc/passwd)
WEBD_UID=$(awk -F: '/^webd:/ {print $3}' /etc/passwd)
DBD_UID=$(awk -F: '/^dbd:/ {print $3}' /etc/passwd)
PARIWALL_UID=$(awk -F: '/^pariwall:/ {print $3}' /etc/passwd)

if [ "$ALICE_UID" -lt 100000 ] || [ "$BOB_UID" -lt 100000 ] || [ "$WEBD_UID" -lt 100000 ] || [ "$PARIWALL_UID" -lt 100000 ]; then
    echo "FAIL: UIDs were sequential instead of random!"
    exit 1
fi

# Verify all preexisting EL10 accounts, memberships, and shadow mode survived account & daemon creation
grep -Fqx "$ORIG_SSHD_PW" /etc/passwd
grep -Fqx "$ORIG_NGINX_PW" /etc/passwd
grep -Fqx "$ORIG_CHRONY_PW" /etc/passwd
grep -Fqx "$ORIG_WHEEL_GR" /etc/group
grep -Fqx "$ORIG_JOURNAL_GR" /etc/group
grep -Fqx "$ORIG_SSHD_SH" /etc/shadow
if grep -q '^#' /etc/passwd /etc/group /etc/shadow; then
    echo "FAIL: invalid '#' comment line found in /etc/{passwd,group,shadow}!"
    exit 1
fi
case "$(stat -c %a /etc/shadow)" in
    0|000|0000) ;;
    *) echo "FAIL: /etc/shadow mode changed after useradd: $(stat -c %a /etc/shadow)"; exit 1 ;;
esac

# Verify distro accounts did NOT gain Pressure credentials or interactive login rights
if pressure-authctl info sshd >/dev/null 2>&1 || \
   grep -q "pub_uid=${ORIG_SSHD_UID} " /sys/kernel/security/pressure/users || \
   grep -q "pub_uid=${ORIG_NGINX_UID} " /sys/kernel/security/pressure/users; then
    echo "FAIL: distro account gained Pressure credentials!"
    exit 1
fi
if press login sshd "anything" /dev/tty1 -- /bin/true 2>/dev/null; then
    echo "FAIL: preexisting distro account 'sshd' was permitted interactive Pressure login!"
    exit 1
fi
echo "PASS: Distro accounts preserved verbatim with zero Pressure credentials or interactive login rights"

# Verify even root (uid=0) outside pressure-authd is hard-stopped from reading auth.vault & posix.manifest!
echo "[4] Verifying kernel hard-stop on /etc/pressure/auth.vault and posix.manifest against root..."
pressure_e2e_test expect-open-denied /etc/pressure/auth.vault
pressure_e2e_test expect-open-denied /etc/pressure/posix.manifest

# 4b. Verify reboot/restart coexistence & interrupted atomic POSIX update recovery
echo "[4b] Testing pressure-authd restart (reboot reconciliation) & interrupted atomic sync recovery..."
AUTHD_PID=$(awk '/^authd_pid:/ {print $2}' /sys/kernel/security/pressure/status)
kill "$AUTHD_PID"
sleep 1
# Simulate an interrupted atomic POSIX swap by planting a rollback backup + corrupt partial entry
cp -p /etc/passwd /etc/.pressure_bak_passwd
printf 'corrupt_partial_entry:x:99999:99999::/tmp:/bin/false\n' >> /etc/passwd
pressure-authd --daemon
sleep 1
[ ! -e /etc/.pressure_bak_passwd ]
if grep -q '^corrupt_partial_entry:' /etc/passwd; then
    echo "FAIL: pressure-authd failed to recover /etc/passwd from interrupted atomic update!"
    exit 1
fi
grep -Fqx "$ORIG_SSHD_PW" /etc/passwd
grep -Fqx "$ORIG_NGINX_PW" /etc/passwd
grep -Fqx "$ORIG_CHRONY_PW" /etc/passwd
grep -Fqx "$ORIG_WHEEL_GR" /etc/group
grep -Fqx "$ORIG_JOURNAL_GR" /etc/group
grep -Fqx "$ORIG_SSHD_SH" /etc/shadow
[ "$(awk -F: '/^alice:/ {print $3}' /etc/passwd)" = "$ALICE_UID" ]
[ "$(awk -F: '/^pariwall:/ {print $3}' /etc/passwd)" = "$PARIWALL_UID" ]
pressure-authctl info alice | grep -q "pub_uid=${ALICE_UID} "
pressure-authctl info pariwall | grep -q "pub_uid=${PARIWALL_UID} "
case "$(stat -c %a /etc/shadow)" in
    0|000|0000) ;;
    *) echo "FAIL: /etc/shadow mode changed after restart: $(stat -c %a /etc/shadow)"; exit 1 ;;
esac
echo "PASS: Reboot/restart reconciliation & interrupted atomic POSIX update recovery verified!"

# 4. Authenticate Alice on local seat /dev/tty1 (max_sessions=1) via PAM (pam_pressure.so):
#    - Transitions system to POSTLOGIN
#    - Verifies random 31-bit non-monotonic unused FDs & /proc/self/fd block
#    - Writes Alice's private workstation file /home/alice/secret_budget.txt
#    - Verifies POSTLOGIN localhost via sfw
echo "[5] Logging in as Alice via PAM (pam_pressure.so) on /dev/tty1..."
press login alice "AliceStrongPass!2026" /dev/tty1 -- /bin/sh -c '
    set -e
    pressure_e2e_test fd-random
    pressure_e2e_test write-file /home/alice/secret_budget.txt "AlicePrivateFamilyData"
    pressure_e2e_test sfw-loopback 19081 check-raw
    pressure_e2e_test sfw-loopback6 19088 check-raw
'
sure status | grep -q "stage:            POSTLOGIN"

# Write private daemon state as dbd daemon
press start-daemon dbd -- pressure_e2e_test write-file /var/lib/dbd/records.db "DaemonSecretRecords"

# 5. Verify Multi-User & Daemon Kernel Hard-Stops:
#    - Bob CANNOT read /home/alice/secret_budget.txt or /var/lib/dbd/records.db
#    - Root (uid=0) without Alice's secret kpriv_uid CANNOT read /home/alice/secret_budget.txt!
#    - Unauthorized setuid(ALICE_UID) without pressure-authd ticket is HARD-STOPPED (-EPERM)!
echo "[6] Verifying secret kpriv_uid hard-stops across Bob, webd daemon, and unauthenticated root..."
pressure_e2e_test expect-open-denied /home/alice/secret_budget.txt
pressure_e2e_test expect-open-denied /var/lib/dbd/records.db
pressure_e2e_test expect-setuid-denied "$ALICE_UID"

press login bob "BobStrongPass!2026" /dev/ttyS0 -- /bin/sh -c "
    set -e
    pressure_e2e_test write-file /home/bob/bob_notes.txt 'BobPrivateData'
    pressure_e2e_test expect-open-denied /home/alice/secret_budget.txt
    pressure_e2e_test expect-open-denied /var/lib/dbd/records.db
"

# 6. Verify /dev Seat Exclusivity (max_sessions=1) & Peripheral Anti-Impersonation:
#    Hold Alice's session open on /dev/tty1 in background; verify a 2nd login on /dev/tty1 is rejected,
#    and verify webd daemon is hard-stopped from /dev/input/event0, /dev/uinput, /dev/sr0, /dev/tty1, and mknod!
echo "[7] Testing /dev seat max_sessions=1 exclusivity & input/storage/mknod lockdown..."
press login alice "AliceStrongPass!2026" /dev/tty1 -- /bin/sleep 3 &
HOLD_PID=$!
sleep 1
if press login bob "BobStrongPass!2026" /dev/tty1 -- /bin/true 2>/dev/null; then
    echo "FAIL: second concurrent session on /dev/tty1 (max_sessions=1) should have been blocked!"
    exit 1
fi
echo "PASS: concurrent session on occupied /dev/tty1 rejected (max_sessions=1)"

press start-daemon webd -- /mnt/host/pressure_e2e_test dev-lockdown
wait "$HOLD_PID" || true

# 6b. Verify TrimOS QuadTap (/dev/quadtap0) max_sessions=1, crash/restart recovery & pre-opened FD privilege drop!
echo "[7b] Testing QuadTap character device exclusivity, crash recovery & privilege-drop FD survival..."
[ -e /dev/quadtap0 ] || mknod /dev/quadtap0 c 7 1
chmod 0666 /dev/quadtap0
cat > /tmp/quadtap_test.pr <<'EOF'
device /dev/quadtap0 label dev:quadtap class other_chr origin remote max_sessions 1;
allow subject subj:daemon_pariwall object dev:quadtap device dev:quadtap events { open, read, write, ioctl } max_prov remote;
deny  subject * object dev:quadtap device dev:quadtap events { all } max_prov remote;
EOF
sure load /tmp/quadtap_test.pr
# 1) webd is denied /dev/quadtap0 by MAC policy
press start-daemon webd -- /mnt/host/pressure_e2e_test expect-open-denied /dev/quadtap0
# 2) pariwall claims /dev/quadtap0 (max_sessions=1); second concurrent pariwall gets EBUSY; SIGKILL crash immediately frees it!
press start-daemon pariwall -- /mnt/host/pressure_e2e_test hold-dev /dev/quadtap0 10 &
QT_PID=$!
sleep 1
if press start-daemon pariwall -- /mnt/host/pressure_e2e_test hold-dev /dev/quadtap0 1 2>/dev/null; then
    echo "FAIL: concurrent second opener on /dev/quadtap0 (max_sessions=1) should have failed!"
    exit 1
fi
kill -9 "$QT_PID" 2>/dev/null || true
wait "$QT_PID" 2>/dev/null || true
press start-daemon pariwall -- /mnt/host/pressure_e2e_test hold-dev /dev/quadtap0 1
# 3) Verify pre-opened FD survives privilege drop into pariwall daemon!
pressure_e2e_test privdrop-fd pariwall
echo "PASS: QuadTap max_sessions=1, SIGKILL crash recovery, and privilege-drop FD survival verified!"

# 6c. Full AF_UNIX Policy Qualification (create/socketpair deny, endpoint isolation, abstract, dgram, SCM_RIGHTS, inherited FD, Nginx <-> PHP-FPM)
echo "[7c] Qualifying AF_UNIX policy (default-deny create/socketpair, abstract/dgram/pass-fd/inherit isolation, Nginx <-> PHP-FPM IPC)..."
mkdir -p /run/php-fpm /run/dgram /run/ipc
chmod 0777 /run/php-fpm /run/dgram /run/ipc
pressure-authctl useradd --daemon web_nginx - --label subj:daemon_nginx
pressure-authctl useradd --daemon phpfpm - --label subj:daemon_phpfpm
pressure-authctl useradd --daemon unixprobe - --label subj:daemon_probe
pressure-authctl useradd --daemon unauth_recv - --label subj:daemon_unauth_recv

# 1) Unauthorized subjects (pariwall with zero AF_UNIX exception, dbd) cannot create AF_UNIX stream/dgram or socketpair
press start-daemon pariwall -- /mnt/host/pressure_e2e_test unix-deny-create
press start-daemon dbd -- /mnt/host/pressure_e2e_test unix-deny-create

# 2) Start authorized PHP-FPM endpoints: pathname stream, abstract stream, pathname dgram, abstract dgram
#    (/run/php-fpm/www.sock accepts 3 connections: authorized Nginx IPC, SCM_RIGHTS pass-fd test, inherited-FD test)
press start-daemon phpfpm -- /mnt/host/pressure_e2e_test unix-stream-server /run/php-fpm/www.sock "*" "FCGI_RESPONSE_OK" 3 &
FPM_PID=$!
press start-daemon phpfpm -- /mnt/host/pressure_e2e_test unix-stream-server @unix_test_abs "*" "ABS_OK" 1 &
ABS_PID=$!
press start-daemon phpfpm -- /mnt/host/pressure_e2e_test unix-dgram-server /run/dgram/test.sock "DGRAM_PATH_OK" &
DG1_PID=$!
press start-daemon phpfpm -- /mnt/host/pressure_e2e_test unix-dgram-server @unix_dgram_abs "DGRAM_ABS_OK" &
DG2_PID=$!
sleep 1

# 3) Create-only subject ('unixprobe') CAN create sockets, CANNOT socketpair, bind, connect, or sendto pathname/abstract endpoints!
press start-daemon unixprobe -- /mnt/host/pressure_e2e_test unix-create-only /run/php-fpm/www.sock @unix_test_abs /run/dgram/test.sock @unix_dgram_abs

# Permit only the packaged test executable for the REMOTE fixture; keep the
# regular remote exec and console descriptor hard-stops in force.
cat > /tmp/unix_fixture_exec.pr <<'EOF'
file /usr/sbin/pressure_e2e_test label obj:unix_fixture;
allow subject subj:daemon_nginx object obj:unix_fixture events { exec } max_prov remote;
EOF
sure load /tmp/unix_fixture_exec.pr
run_remote_unix_fixture() {
    if press start-daemon web_nginx --remote -- /usr/sbin/pressure_e2e_test "$@" >/tmp/unix_fixture.log 2>&1; then
        cat /tmp/unix_fixture.log
    else
        cat /tmp/unix_fixture.log
        return 1
    fi
}

# 4) Authorized Nginx (--remote, tainted REMOTE!) <-> PHP-FPM stream IPC & pathname/abstract datagrams work under enforce=1!
run_remote_unix_fixture unix-stream-client /run/php-fpm/www.sock "FCGI_REQ_GET_INDEX" "FCGI_RESPONSE_OK"
run_remote_unix_fixture unix-dgram-client /run/dgram/test.sock "DGRAM_PATH_OK"
run_remote_unix_fixture unix-dgram-client @unix_dgram_abs "DGRAM_ABS_OK"
wait "$DG1_PID"
wait "$DG2_PID"

# 5) Passed AF_UNIX descriptor (SCM_RIGHTS) to unauthorized subject ('unauth_recv') is blocked by file_receive!
press start-daemon unauth_recv -- /mnt/host/pressure_e2e_test unix-passfd-receiver /run/ipc/carrier.sock &
RECV_PID=$!
sleep 1
run_remote_unix_fixture unix-passfd-sender /run/ipc/carrier.sock /run/php-fpm/www.sock
wait "$RECV_PID"

# 6) Inherited AF_UNIX descriptor across privilege drop into unauthorized subject ('unixprobe') is blocked!
pressure_e2e_test unix-inherit-deny /run/php-fpm/www.sock unixprobe
wait "$FPM_PID"
kill "$ABS_PID" 2>/dev/null || true
wait "$ABS_PID" 2>/dev/null || true
echo "PASS: Full AF_UNIX policy qualification (default-deny, abstract, dgram, SCM_RIGHTS, inherited FD, Nginx <-> PHP-FPM) verified!"

# 6d. TrimOS Router Console (/dev/tty1) Verification, Anti-Spoofing, Protected Files & Revocation
echo "[7d] Qualifying TrimOS Router /dev/tty1 console enforcement, anti-spoofing, protected files & revocation..."
mkdir -p /etc/trimos/router /run/trimos
chmod 0777 /etc/trimos/router /run/trimos
printf 'INITIAL_ROUTER_CFG\n' > /etc/trimos/router/router.conf
chmod 0666 /etc/trimos/router/router.conf

pressure-authctl useradd routeradmin "RouterAdmin!2026" --label subj:user_routeradmin
pressure-authctl useradd --daemon routerctl - --label subj:daemon_routerctl

cat > /tmp/router_console_test.pr <<'EOF'
device /dev/tty1  label dev:console_tty1 class seat_tty origin local max_sessions 1;
device /dev/tty2  label dev:seat_tty     class seat_tty origin local max_sessions 1;
device /dev/tty3  label dev:seat_tty     class seat_tty origin local max_sessions 1;
device /dev/ttyS0 label dev:serial_tty   class seat_tty origin local max_sessions 1;

file /etc/trimos/router label obj:router_cfg flags { local_only, protected };
file /etc/trimos/router/router.conf label obj:router_cfg flags { local_only, protected };

# Only the qualification executable runs as the remote router test subject.
allow subject subj:user_routeradmin object obj:unix_fixture events { exec } max_prov remote;

allow subject subj:user_routeradmin object obj:router_cfg device dev:console_tty1 events { open, read, write } max_prov auth_local;
allow subject subj:daemon_routerctl object obj:router_cfg device dev:service events { open, read, write } max_prov auth_local;
allow subject subj:daemon_pariwall  object obj:router_cfg device dev:service events { open, read } max_prov remote;
deny  subject * object obj:router_cfg device * events { all } max_prov remote;

unix_socket allow subject subj:daemon_routerctl type stream ops { create, bind, send, recv } endpoint /run/trimos/router-admin.sock peer * device dev:service max_prov auth_local;
unix_socket allow subject subj:user_routeradmin type stream ops { create, connect, send, recv } endpoint /run/trimos/router-admin.sock peer subj:daemon_routerctl device dev:console_tty1 max_prov auth_local;
set enforce on;
EOF
sure check /tmp/router_console_test.pr
sure load /tmp/router_console_test.pr

# Start routerctl admin control socket daemon (service-specific access independent of interactive login)
press start-daemon routerctl -- /mnt/host/pressure_e2e_test unix-stream-server /run/trimos/router-admin.sock "*" "ROUTER_ADMIN_ACK" 2 &
RCTL_PID=$!
sleep 1

# 1) Pre-login / unauthenticated users & unauthorized daemons are denied
pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock prelogin-boot
press exec --label subj:user_routeradmin -- /mnt/host/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock unauth-human
press start-daemon webd -- /mnt/host/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock unauth-daemon-webd

# 2) Authorized daemons retain service-specific access independent of interactive login
press start-daemon routerctl -- /mnt/host/pressure_e2e_test write-file /etc/trimos/router/router.conf "ROUTERCTL_DAEMON_OK\n"
press start-daemon pariwall -- /bin/sh -c 'cat /etc/trimos/router/router.conf >/dev/null'
if press start-daemon pariwall -- /mnt/host/pressure_e2e_test write-file /etc/trimos/router/router.conf "PARIWALL_WRITE_FAIL" 2>/dev/null; then
    echo "FAIL: read-only daemon pariwall was allowed to write protected router.conf!"
    exit 1
fi
echo "PASS: Service-specific daemon access (routerctl RW, pariwall RO, webd denied) verified"

# 3) Authenticated routeradmin on verified /dev/tty1 succeeds (and MAP_SHARED write & setsid() detach are blocked!)
printf '%s\n' 'RouterAdmin!2026' | press login routeradmin --password-stdin /dev/tty1 -- /mnt/host/pressure_e2e_test router-admin-allow /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock

# 4) Authenticated routeradmin on tty2, tty3, serial ttyS0, local graphical PTY, and SSH are ALL denied!
press login routeradmin "RouterAdmin!2026" /dev/tty2 -- /mnt/host/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock tty2
press login routeradmin "RouterAdmin!2026" /dev/tty3 -- /mnt/host/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock tty3
press login routeradmin "RouterAdmin!2026" /dev/ttyS0 -- /mnt/host/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock serial-ttyS0
press login routeradmin "RouterAdmin!2026" pty --pty -- /mnt/host/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock local-graphical-pty
if press login routeradmin "RouterAdmin!2026" pty --pty --rhost 192.0.2.50 -- /usr/sbin/pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock ssh-pty >/tmp/router_remote_fixture.log 2>&1; then
    cat /tmp/router_remote_fixture.log
else
    cat /tmp/router_remote_fixture.log
    exit 1
fi

# 5) Spoofing PAM_TTY=/dev/tty1 from a PTY or /dev/tty2 MUST be rejected by kernel!
if press login routeradmin "RouterAdmin!2026" pty --pty --spoof-tty /dev/tty1 -- /bin/true 2>/dev/null; then
    echo "FAIL: spoofed PAM_TTY=/dev/tty1 from PTY was NOT rejected by kernel!"
    exit 1
fi
if press login routeradmin "RouterAdmin!2026" /dev/tty2 --spoof-tty /dev/tty1 -- /bin/true 2>/dev/null; then
    echo "FAIL: spoofed PAM_TTY=/dev/tty1 from /dev/tty2 was NOT rejected by kernel!"
    exit 1
fi
echo "PASS: Kernel rejected spoofed /dev/tty1 pathname claims from PTY and /dev/tty2 (TTY_SPOOF_BLOCKED)"

# 6) Open file & admin socket descriptors held across logout are immediately revoked!
rm -f /tmp/post_logout_result.txt
press login routeradmin "RouterAdmin!2026" /dev/tty1 -- /mnt/host/pressure_e2e_test router-hold-across-logout /etc/trimos/router/router.conf /run/trimos/router-admin.sock /tmp/post_logout_result.txt
sleep 3
grep -q "POST_LOGOUT_REVOKED_OK" /tmp/post_logout_result.txt
pressure_e2e_test router-admin-deny /etc/trimos/router /etc/trimos/router/router.conf /run/trimos/router-admin.sock post-logout
wait "$RCTL_PID"

# 7) Grant TTL expiry revokes already-open protected file descriptors!
press login routeradmin "RouterAdmin!2026" /dev/tty1 --ttl 2 -- /mnt/host/pressure_e2e_test router-expiry /etc/trimos/router/router.conf 3
echo "PASS: TrimOS Router /dev/tty1 console enforcement, anti-spoofing, post-logout & TTL revocation verified!"

# 7. Verify REMOTE Server Worker Containment (localhost sfw block, RWX mmap block, execve block)
echo "[8] Verifying REMOTE provenance containment (web/PHP RCE prevention)..."
press start-daemon webd -- /mnt/host/pressure_e2e_test remote-containment

# 8. Verify 3-Strike Audit Log & Uncatchable Kernel SIGKILL
echo "[9] Verifying 3-strike FD/provenance violation audit + uncatchable SIGKILL..."
press login alice "AliceStrongPass!2026" /dev/tty1 -- /mnt/host/pressure_e2e_test three-strikes

echo "[10] Generating final 'sure report' & 'sure devices'..."
sure devices | head -n 15
sure report

echo ""
echo "ALL_PRESSURE_TESTS_PASSED"
