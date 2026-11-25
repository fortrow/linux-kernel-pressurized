# 05 — `sure` Administration CLI & Declarative `.pr` Policy Language

**`sure`** ([userspace/sure/sure.c](../userspace/sure/sure.c), [policy_parser.h](../userspace/sure/policy_parser.h), [policy_parser.c](../userspace/sure/policy_parser.c)) is the reporting, labeling, audit inspection, and declarative policy compiler/loader for Pressure and `sfw`.

---

## 1. `sure` CLI Subcommands

```bash
# Kernel status, stage (PRELOGIN/POSTLOGIN), and registered accounts (secret kpriv_uids redacted)
sure status

# Security violation summary + 3-strike SIGKILL audit log
sure report
sure audit

# List cryptographic /dev (major:minor) and net_device (ifindex) table
sure devices

# Imperatively update a /dev node or network interface label/class/provenance/max_sessions
sure dev-label /dev/tty1 dev:seat_tty 1 local 1
sure dev-label eth0 dev:net_ext 6 remote 0

# Imperatively tag a file or directory (writes security.pressure xattr + pins kernel inode blob)
sure file-label /etc/pam.d/pressure-login obj:pam_cfg --local-only
sure file-label /home/alice subj:user_alice --local-only --user-private 1491580430
sure file-label /etc/pressure/auth.vault obj:authd_vault --vault

# Imperatively inspect, add, or flush 6-tuple event policy rules
sure policy list
sure policy flush
sure policy add deny subj:web_php obj:local_cfg * 0x1fff 2

# Validate (dry-run), transactionally load (with automatic rollback), or check admission readiness
sure load  /usr/share/pressure/policies/server.pr
sure ready --require-sfw
```

---

## 2. Declarative `.pr` Policy Language Specification

Implemented in [policy_parser.c](../userspace/sure/policy_parser.c) (~1,170 lines), `.pr` files allow administrators to express device confinement, file labels, 6-tuple event rules, dual-stack `sfw` socket rules, 5-chain packet rules, and NAT44/NAT66 rules in a single human-readable, pre-validated configuration file.

### 2.1 Two-Phase Compilation, Pre-Flight & Transactional Kernel Rollback
1. **Phase 1 (`sure check` & `sure load`)**: Parses statements, expands `$VARIABLES`, resolves `include` files (up to depth `8`), validates all keywords, label lengths (`< 32`), event names, port ranges (`0..65535`, `min <= max`), and IPv4/IPv6 addresses/CIDRs (`inet_pton`), compiling into an in-memory `struct pr_compiled_op` array. Any syntax or semantic error prints an exact `file:line` diagnostic and exits non-zero **before touching kernel state**.
2. **Phase 2 (`sure load` only — Pre-Flight + Kernel Snapshot Transaction)**:
   - Verifies `/proc/pressure_sfw/chains` exists if packet/NAT rules are used, and checks that all non-`optional` `device`, `netdev` (`/sys/class/net/<ifname>`), and `file` targets exist before opening a transaction.
   - Writes `"begin\n"` to `/sys/kernel/security/pressure/txn` and (when `sfw.ko` is loaded) `/proc/pressure_sfw/txn` **before any policy edits**. If `"begin"` fails (`-EBUSY` concurrent loader or unavailable `txn`), `sure load` stops immediately with exit code `1` without modifying active policy.
   - Applies operations sequentially, then runs two-phase **`"prepare\n"` $\rightarrow$ `"commit\n"`** across both subsystems.
   - If any apply or `prepare` step fails, `sure load` checks all xattr and `"abort\n"` rollback return codes:
     - **Exit `0`**: Clean commit (`policy_gen` & `sfw_policy_gen` incremented; `txn_degraded` cleared).
     - **Exit `1`**: Clean rollback completed; previous active policy is preserved.
     - **Exit `2`**: Partial cross-subsystem commit or rollback error; latches `txn_degraded=1` in the kernel so `sure ready` blocks service admission until a clean recovery `sure load` succeeds.

### 2.2 Lexical Rules, Variables & Includes
- **Comments**: `#` through end-of-line.
- **Statements**: Whitespace-insensitive, multi-line supported, terminated by `;`.
- **Variables (`define`)**:
  ```text
  define $LAN4    = 10.10.0.0/24;
  define $LAN6    = fd00:10::/64;
  define $WAN6_GW = fd00:20::1/128;
  ```
  Variables expand both standalone (`$LAN6`) and inline inside composite tokens.
- **Includes (`include`)**:
  ```text
  include "common-devices.pr";
  ```
  Relative paths resolve relative to the directory containing the current `.pr` file.

---

### 2.3 Complete Statement Grammar

#### Enforcement & Policy Reset
```text
set enforce <on | off | 1 | 0>;
policy flush;
```

#### `/dev` Character/Block & Network Device Confinement
```text
device <path_or_maj:min>
    label <label>
    class <pseudo_safe | seat_tty | seat_input | storage_blk | pty | net_lo | net_ext | other_chr>
    [origin <local | remote>]
    [max_sessions <0..65535>]
    [optional];

netdev <ifname>
    label <label>
    class <net_lo | net_ext>
    [origin <local | remote>]
    [max_sessions <0..65535>]
    [optional];
```
- Adding `optional` skips missing hardware nodes gracefully during `sure load` (ideal for portable workstation/server profiles), whereas omitting `optional` fails hard if the device is absent.

#### File & Directory Hard-Stop Labeling
```text
file <path>
    label <label>
    [flags { local_only, user_private, vault, protected }]
    [owner <pub_uid>]
    [optional];
```
- Adding `protected` makes unmatched access to that file/directory (and newly instantiated children inside a `protected` directory) **default-deny** in enforcing mode across `open`, `read`, `write`, `ioctl`, `inode_create`, `mkdir`, `symlink`, `link`, `unlink`, `rmdir`, `rename`, `setattr`/`truncate`, `mmap_file`, and `file_mprotect`.

#### 6-Tuple Subject / Object / Device / Event / Provenance Rules
```text
<allow | deny>
    subject <subj_label | prefix* | *>
    object <obj_label | *>
    [device <dev_label | *>]
    events { open, read, write, ioctl, mknod, exec, mmap_exec, mmap_write,
             setuid, sock_bind, sock_connect, sock_send, sock_recv, login, all }
    max_prov <prelogin_local | auth_local | remote>;
```
- For regular files and protected directories, `device` matches the caller's **live, kernel-verified controlling terminal/session label** (e.g., `dev:console_tty1` for `/dev/tty1`, `dev:seat_tty` for `/dev/tty2+`, `dev:serial_tty` for `/dev/ttyS*`, `dev:pty` for local PTYs, `dev:service` for daemons, or `dev:none` for unauthenticated/SSH/detached/revoked/expired sessions).
- Write-capable `MAP_SHARED | PROT_WRITE` mappings require `mmap_write` in addition to `write`, preventing interactive sessions from establishing unrevocable shared write mappings across logout unless explicitly permitted.

#### `AF_UNIX` Socket Creation, Endpoint & Descriptor-Transfer Rules
```text
unix_socket flush;

unix_socket <allow | deny>
    [subject <subj_label | prefix* | *>]
    [executable <exact_obj_label>]
    [type <stream | dgram | seqpacket | any | *>]
    ops { create, socketpair, bind, connect, send, recv, pass_fd, all }
    [endpoint <- | /abs/path | /prefix/* | @abstract | @prefix* | pair:* | *>]
    [peer <peer_label | prefix* | *>]
    [device <dev_label | *>]
    max_prov <prelogin_local | auth_local | remote>;
```
- **Default-Deny in Enforcing Mode**: When `enforce = 1`, `socket(AF_UNIX, ...)` and `socketpair(AF_UNIX, ...)` are denied (`-EACCES`, `UNIX_SOCKET_POLICY_DENY`) unless matched by an explicit `unix_socket allow` rule for the subject, socket type, and provenance.
- **Separation of Creation vs. Endpoint Access**: A creation-only rule (`ops { create } endpoint -`) NEVER matches `bind`, `connect`, `send`, `recv`, or `pass_fd` operations. Endpoint operations require an explicit `endpoint` (rejected at `sure check` time if `-`).
- **Descriptors Passed (`SCM_RIGHTS`) or Inherited**: Receiving an `AF_UNIX` FD via `SCM_RIGHTS` (`file_receive`) or using a cross-subject inherited `AF_UNIX` FD (`file_fd_lookup`) requires explicit `pass_fd` authorization for that socket's canonical endpoint and peer.
- **Executable scope** adds an exact match on the calling process's executable inode label. For example, use `executable obj:chatgpt_exec` with a labeled binary to scope a socket-pair grant. The subject, device, endpoint, peer, and provenance checks still apply. The scoped rule format requires an updated kernel and `sure`.
- **Detached tty1 helpers** can use `device dev:tty1_helper` for local stream sockets. Pressure verifies the inherited session grant and the original leader's live controlling tty1. The rule requires an exact subject and executable, `auth_local` provenance, and either socket creation or same-subject anonymous socket-pair operations. The loopback proxy rule below can also use this device context.

#### POSIX descriptor ABI for a local desktop session

An exact login rule can select conventional POSIX descriptor numbering
for a verified local human session. Bash requires this ABI for fixed
descriptor redirects and ordinary descriptor probes.

```text
allow subject subj:user_desktop object obj:posix_fd_abi device dev:console_tty1 events { login } max_prov auth_local;
```

Pressure evaluates the exact subject, reserved object, live device
label, login event, and local provenance when consuming the UID ticket.
The ABI is inherited with the session's file table. Existing tokenized
file tables are kept as-is. File authorization, AF_UNIX checks, and
session revocation still apply. Sessions without an exact matching
allow use descriptor tokens.

#### Session-Scoped Loopback Proxy

A static application can use a supervised SFW CONNECT gateway with an
explicit `local_proxy` rule:

```text
allow subject subj:user_desktop object obj:chatgpt_helper device dev:tty1_helper events { local_proxy } max_prov auth_local;
```

Use an exact subject and executable object, `dev:console_tty1` or
`dev:tty1_helper`, and `auth_local`. The rule authorizes only an IPv4 TCP
client connection to `127.0.0.1:18443` in the initial network namespace.
It requires a live session and rechecks the executable and session on
socket I/O. Receiving from the gateway marks the caller as remotely tainted.
An established tunnel can continue under the same verified session, while
creation and connection still require local provenance. This grant alone
does not authorize bind or listen. The socket cannot be received through
`SCM_RIGHTS`. Start the trusted gateway
before enabling enforcement and configure its upstream allowlist separately.

The separate `local_callback` event uses the same exact-label and
authenticated tty1 requirements. On a socket created with `local_proxy`,
it authorizes a TCP listener at `127.0.0.1:1455`. Accepted connections
inherit the listener's session and require the callback grant for descriptor
lookup and I/O. Receiving callback data marks the caller as remotely tainted.

Use `local_callback_relay` on the trusted adapter executable to grant an
IPv4 TCP client connection to `127.0.0.1:1455`. It requires a separate
exact authenticated tty1 rule. A relay socket cannot bind or listen.
An executable with both a proxy rule and a relay rule creates proxy
sockets. Assign the relay to its own executable label.

#### Dual-Stack `AF_UNIX` `sfw` Socket Worker Rules
```text
sfw_socket flush;

sfw_socket <allow | deny> <any | bind | connect | send | recv>
    [uid <pub_uid | 0 | *>]
    dst <ipv4_cidr | ipv6_cidr | *>
    [ports <port | pmin-pmax | *>]
    [dev <dev_label_or_ifname | *>]
    max_prov <prelogin_local | auth_local | remote>;
```
- IPv4 CIDRs (e.g. `127.0.0.0/8`, `192.168.1.0/24`) automatically convert prefix lengths into dotted netmasks for `/sys/kernel/security/pressure/sfw_rules`.
- IPv6 CIDRs (e.g. `::1/128`, `2001:db8::/64`, `::/0`) automatically emit `inet6 ...` rules.

#### Dual-Stack 5-Chain Stateful Packet Rules
```text
sfw_chain flush;
sfw_chain policy <prerouting | input | forward | output | postrouting> <accept | allow | drop>;

sfw_chain <allow | accept | drop> <prerouting | input | forward | output | postrouting>
    [proto <tcp | udp | icmp | icmpv6 | all>]
    [in <ifname_or_dev_label | *>]
    [out <ifname_or_dev_label | *>]
    [src <ipv4_cidr | ipv6_cidr | *>]
    [dst <ipv4_cidr | ipv6_cidr | *>]
    [dports <port | pmin-pmax | *>]
    [state <any | new | established>];
```
- Rules with `src *` and `dst *` compile with `family = 0` (`any`), matching both IPv4 and IPv6 traffic simultaneously; rules specifying IPv4 or IPv6 CIDRs enforce family consistency between `src` and `dst`.

#### Dual-Stack Stateful NAT (`MASQUERADE`, `SNAT`, `DNAT` Port-Forwarding)
```text
sfw_nat flush;

# Dynamic outgoing interface IP selection (NAT44 & NAT66)
sfw_nat masquerade out <out_dev> src <ipv4_cidr | ipv6_cidr>;

# Static source NAT (NAT44 & NAT66)
sfw_nat snat [proto <tcp | udp | all>] out <out_dev> src <cidr> to <snat_ip>;

# Destination NAT / Port-Forwarding (IPv4 ip:port or bracketed IPv6 [ip6]:port)
sfw_nat dnat [proto <tcp | udp | all>] [in <in_dev | *>] [dst <cidr | *>] dport <port> to <ip4>:<port>;
sfw_nat dnat [proto <tcp | udp | all>] [in <in_dev | *>] [dst <cidr | *>] dport <port> to [<ip6>]:<port>;
```

---

A detached application helper that needs to inspect its own POSIX descriptors
requires a separate `proc_self_fd` rule. Use exact subject and executable labels
with an authenticated tty1 context.

```pressure
allow subject subj:user_desktop object obj:chatgpt_exec device dev:tty1_helper events { proc_self_fd } max_prov auth_local;
```

## 3. Bundled Reference Policy Profiles

Installed into `/usr/share/pressure/policies/` inside the initramfs and `dev/shared/policies/`:
- **[server.pr](../userspace/policies/server.pr)** — Dual-stack server & NAT44/NAT66 gateway profile: confines `subj:web_php` workers against TTYs, block storage, `exec`, `mmap_exec`, `mknod`, and `setuid`; sets `forward` default policy to `drop`; enables stateful `established` return traffic plus live IPv4 and IPv6 `masquerade` and `dnat` port-forwarding.

### Search Pressure audit events

Use exact filters together to narrow the audit to a command, PID, parent
PID, public UID, reason, or action. Results retain the raw audit fields.
The live search reads the kernel's retained audit ring using its existing
permissions. Use a saved report to search after a reboot.

```sh
sure search --comm wget --action SIGKILL
sure search --ppid 115 --reason UNIX_SOCKET_POLICY_DENY
sure search --pid 172 --tid 372
sure search --subject subj:user_routeradmin --device dev:console_tty1 --prov AUTH_LOCAL
sure search --file desktop-serial.log --comm bash
```

Audit records report `pid` for the process and `tid` for the thread
that triggered the denial. `comm` names that thread. The recorded
provenance includes any remote taint applied to the thread.

Use `--file -` for standard input. Search exits with 0 for matching
events, 1 for zero matches, and 2 for usage or I/O errors.

### Draft a policy interactively

Run `press auto` and enter the sequence number from `sure search`. To
save a draft or use a captured audit, specify the sequence explicitly.

```sh
press auto --seq 3 --file desktop-serial.log > candidate.pr
sure check candidate.pr
```

Drafts cover authenticated local object-policy, AF_UNIX, registered
device-policy, and SFW socket denials.
Object-policy records supply the object label and the recorded event
bits. Current kernels also record the subject and verified device
used in the policy decision. `press auto` reuses those exact labels.
Older object records prompt for the missing labels. An event with
`dev:none` or remote provenance yields no draft.

Current AF_UNIX creation, socketpair, bind, connect, send, and receive
records include the operation and the subject and device evaluated by
the kernel. The draft uses the recorded endpoint and peer when the
hook knows both. When a check runs before the peer is established,
enter the exact peer label from independent evidence. Legacy records
still prompt for details when those details can be verified. Creation
rules use `endpoint -`. Bind rules omit the peer. Descriptor-transfer
drafts require independently verified evidence.

For a registered device denial, confirm the device identity and one
operation. This can draft a discretionary rule for the recorded
device label. Seat and identity hard-stops still apply.

For SFW, the draft preserves the recorded public UID, direction, and
port. Verify the device label against the recorded interface. IPv4
uses the recorded address as a /32. IPv6 requires the full address
from independent evidence because the audit stores only its low 32
bits. The rule uses a /128. Use `sure devices` to verify the interface
mapping and confirm that the UID still belongs to the intended account
when working from a saved log. UID 0 and unspecified addresses or
ports produce no draft. Direct IP socket blocks and other hard-stops
require diagnosis and produce no allow rule.

Verify the real subject and device labels before entering them. Prompts
go to standard error and the draft goes to standard output. Review rule
ordering in the destination profile before applying a draft. The
command leaves the running policy unchanged.
