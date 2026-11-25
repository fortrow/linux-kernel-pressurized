# Linux Kernel, Pressurized

Linux Kernel, Pressurized is a Linux 7.3.5 source tree with Pressure, a Linux Security Module (LSM) for authorizing operations using identity, provenance, and session context. Its central question is whether a particular process, acting in its current session, is allowed to perform this operation on this object.

## What “pressurized” means

A policy can distinguish an authenticated local session from a remote or unauthenticated process. It can also distinguish a service from a person, and a verified controlling terminal from a terminal name supplied by userspace. With the appropriate labels and rules, an administrator at the physical console can modify a protected file while a service can read it and a remote session is denied. Session-bound access is reevaluated as the kernel observes logout, expiry, or terminal detachment.

## Pressure, press, and sure

| Component | Role |
| --- | --- |
| **Pressure** | The [kernel LSM](security/pressure/) applies policy at kernel hooks for protected files, devices, execution, and sockets. It tracks authenticated session context and exposes policy and audit interfaces through securityfs. |
| **`press`** | The [session and process CLI](userspace/press/) starts PAM-authenticated sessions, launches labeled daemons, and runs confined processes. `press auto` can draft rules from audit events for review. |
| **`sure`** | The [policy and audit CLI](userspace/sure/) validates and loads declarative `.pr` policies and provides tools for inspecting labels, status, and audit events. |

A typical policy workflow starts with `sure search` to inspect a denial. Use `press auto` to draft a rule, review its subject, object, operation, and session scope, then validate it with `sure check`. An authorized administrator applies the reviewed policy with `sure load`.

[Pressure authd](userspace/authd/) and [the PAM module](userspace/pam/) connect authentication to kernel session grants. The bundled [PAM service](userspace/pam/pressure-login) shows the guest login stack. [SFW](modules/sfw/) is the companion socket firewall, with socket policy, packet filtering, forwarding, and NAT. The supplied Pressure configurations enable Pressure and disable SELinux and Netfilter.

## Build and try it

Use an x86-64 Linux build host with a kernel toolchain, ccache, and PAM and OpenSSL development headers. The guest harness also needs QEMU, a static BusyBox, and the utilities listed in the [build guide](docs/06-build-qemu-and-testing.md).

```sh
make -f dev/Makefile kernel
make -C userspace
make -C modules/sfw
cp modules/sfw/sfw.ko dev/shared/
make -f dev/Makefile initramfs
./dev/run-qemu.sh --pressure-test
```

The harness uses a [QEMU development fragment](dev/kernel.config.fragment). The [base TrimOS Server kernel configuration](configs/trimos-server-x86_64.config) and [reference Server policy](userspace/policies/server.pr) are included as starting points. Validate policy syntax with `dev/shared/sure check userspace/policies/server.pr`. Use a disposable VM to test authentication and enforcement before applying a policy to a deployed system.

## Documentation and licensing

See the [Pressure documentation](docs/README.md) for kernel internals, SFW, authentication, policy syntax, and testing.

The Linux kernel and the integrated Pressure LSM are licensed under **GPL-2.0-only**. The kernel’s [COPYING notice](COPYING) references the [GPLv2 license text](LICENSES/preferred/GPL-2.0) and the [Linux syscall exception](LICENSES/exceptions/Linux-syscall-note). See the SPDX identifiers in individual source files for their applicable terms.
