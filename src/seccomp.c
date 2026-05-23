// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2022-2024 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 */
#include "include/ruri.h"
/*
 * This file provides the built-in seccomp filter rules for ruri.
 * Thanks docker for denied syscall list.
 */
// Reslove prefix for errno.
#ifndef DISABLE_LIBSECCOMP
#define ruri_seccomp_rule_add(container, ...)                                                                               \
	do {                                                                                                                \
		int ret__ = seccomp_rule_add(__VA_ARGS__);                                                                  \
		if (ret__ < 0 && ret__ != -EEXIST) {                                                                        \
			ruri_warn_on_error(1, 0, !container->no_warnings, "seccomp rule add failed: %s", strerror(-ret__)); \
		}                                                                                                           \
	} while (0)
static int ruri_resolve_seccomp_errno(const char *_Nonnull syscall, scmp_filter_ctx *_Nonnull ctx)
{
	const char *syscall_name = syscall;
	uint32_t action = SCMP_ACT_KILL;
	// Support errno prefixes like EACCES:chroot, EPERM:unshare, etc.
	// clang-format off
	struct {
  		const char *name;
  		unsigned int value;
	} errno_map[] = {{"ERRNO:", 0},
                 {"E2BIG:", E2BIG},
                 {"EACCES:", EACCES},
                 {"EADDRINUSE:", EADDRINUSE},
                 {"EADDRNOTAVAIL:", EADDRNOTAVAIL},
                 {"EAFNOSUPPORT:", EAFNOSUPPORT},
                 {"EAGAIN:", EAGAIN},
                 {"EALREADY:", EALREADY},
                 {"EBADE:", EBADE},
                 {"EBADF:", EBADF},
                 {"EBADFD:", EBADFD},
                 {"EBADMSG:", EBADMSG},
                 {"EBADR:", EBADR},
                 {"EBADRQC:", EBADRQC},
                 {"EBADSLT:", EBADSLT},
                 {"EBUSY:", EBUSY},
                 {"ECANCELED:", ECANCELED},
                 {"ECHILD:", ECHILD},
                 {"ECHRNG:", ECHRNG},
                 {"ECOMM:", ECOMM},
                 {"ECONNABORTED:", ECONNABORTED},
                 {"ECONNREFUSED:", ECONNREFUSED},
                 {"ECONNRESET:", ECONNRESET},
                 {"EDEADLK:", EDEADLK},
                 {"EDEADLOCK:", EDEADLOCK},
                 {"EDESTADDRREQ:", EDESTADDRREQ},
                 {"EDOM:", EDOM},
                 {"EDQUOT:", EDQUOT},
                 {"EEXIST:", EEXIST},
                 {"EFAULT:", EFAULT},
                 {"EFBIG:", EFBIG},
                 {"EHOSTDOWN:", EHOSTDOWN},
                 {"EHOSTUNREACH:", EHOSTUNREACH},
                 {"EHWPOISON:", EHWPOISON},
                 {"EIDRM:", EIDRM},
                 {"EILSEQ:", EILSEQ},
                 {"EINPROGRESS:", EINPROGRESS},
                 {"EINTR:", EINTR},
                 {"EINVAL:", EINVAL},
                 {"EIO:", EIO},
                 {"EISCONN:", EISCONN},
                 {"EISDIR:", EISDIR},
                 {"EISNAM:", EISNAM},
                 {"EKEYEXPIRED:", EKEYEXPIRED},
                 {"EKEYREJECTED:", EKEYREJECTED},
                 {"EKEYREVOKED:", EKEYREVOKED},
                 {"EL2HLT:", EL2HLT},
                 {"EL2NSYNC:", EL2NSYNC},
                 {"EL3HLT:", EL3HLT},
                 {"EL3RST:", EL3RST},
                 {"ELIBACC:", ELIBACC},
                 {"ELIBBAD:", ELIBBAD},
                 {"ELIBMAX:", ELIBMAX},
                 {"ELIBSCN:", ELIBSCN},
                 {"ELIBEXEC:", ELIBEXEC},
                 {"ELNRNG:", ELNRNG},
                 {"ELOOP:", ELOOP},
                 {"EMEDIUMTYPE:", EMEDIUMTYPE},
                 {"EMFILE:", EMFILE},
                 {"EMLINK:", EMLINK},
                 {"EMSGSIZE:", EMSGSIZE},
                 {"EMULTIHOP:", EMULTIHOP},
                 {"ENAMETOOLONG:", ENAMETOOLONG},
                 {"ENETDOWN:", ENETDOWN},
                 {"ENETRESET:", ENETRESET},
                 {"ENETUNREACH:", ENETUNREACH},
                 {"ENFILE:", ENFILE},
                 {"ENOANO:", ENOANO},
                 {"ENOBUFS:", ENOBUFS},
                 {"ENODATA:", ENODATA},
                 {"ENODEV:", ENODEV},
                 {"ENOENT:", ENOENT},
                 {"ENOEXEC:", ENOEXEC},
                 {"ENOKEY:", ENOKEY},
                 {"ENOLCK:", ENOLCK},
                 {"ENOLINK:", ENOLINK},
                 {"ENOMEDIUM:", ENOMEDIUM},
                 {"ENOMEM:", ENOMEM},
                 {"ENOMSG:", ENOMSG},
                 {"ENONET:", ENONET},
                 {"ENOPKG:", ENOPKG},
                 {"ENOPROTOOPT:", ENOPROTOOPT},
                 {"ENOSPC:", ENOSPC},
                 {"ENOSR:", ENOSR},
                 {"ENOSTR:", ENOSTR},
                 {"ENOSYS:", ENOSYS},
                 {"ENOTBLK:", ENOTBLK},
                 {"ENOTCONN:", ENOTCONN},
                 {"ENOTDIR:", ENOTDIR},
                 {"ENOTEMPTY:", ENOTEMPTY},
                 {"ENOTRECOVERABLE:", ENOTRECOVERABLE},
                 {"ENOTSOCK:", ENOTSOCK},
                 {"ENOTSUP:", ENOTSUP},
                 {"ENOTTY:", ENOTTY},
                 {"ENOTUNIQ:", ENOTUNIQ},
                 {"ENXIO:", ENXIO},
                 {"EOPNOTSUPP:", EOPNOTSUPP},
                 {"EOVERFLOW:", EOVERFLOW},
                 {"EOWNERDEAD:", EOWNERDEAD},
                 {"EPERM:", EPERM},
                 {"EPFNOSUPPORT:", EPFNOSUPPORT},
                 {"EPIPE:", EPIPE},
                 {"EPROTO:", EPROTO},
                 {"EPROTONOSUPPORT:", EPROTONOSUPPORT},
                 {"EPROTOTYPE:", EPROTOTYPE},
                 {"ERANGE:", ERANGE},
                 {"EREMCHG:", EREMCHG},
                 {"EREMOTE:", EREMOTE},
                 {"EREMOTEIO:", EREMOTEIO},
                 {"ERESTART:", ERESTART},
                 {"ERFKILL:", ERFKILL},
                 {"EROFS:", EROFS},
                 {"ESHUTDOWN:", ESHUTDOWN},
                 {"ESPIPE:", ESPIPE},
                 {"ESOCKTNOSUPPORT:", ESOCKTNOSUPPORT},
                 {"ESRCH:", ESRCH},
                 {"ESTALE:", ESTALE},
                 {"ESTRPIPE:", ESTRPIPE},
                 {"ETIME:", ETIME},
                 {"ETIMEDOUT:", ETIMEDOUT},
                 {"ETOOMANYREFS:", ETOOMANYREFS},
                 {"ETXTBSY:", ETXTBSY},
                 {"EUCLEAN:", EUCLEAN},
                 {"EUNATCH:", EUNATCH},
                 {"EUSERS:", EUSERS},
                 {"EWOULDBLOCK:", EWOULDBLOCK},
                 {"EXDEV:", EXDEV},
                 {"EXFULL:", EXFULL}};
	// clang-format on
	for (size_t i = 0; i < sizeof(errno_map) / sizeof(errno_map[0]); i++) {
		if (strncmp(syscall_name, errno_map[i].name, strlen(errno_map[i].name)) == 0) {
			action = SCMP_ACT_ERRNO(errno_map[i].value);
			syscall_name += strlen(errno_map[i].name);
			int syscall_nr = seccomp_syscall_resolve_name(syscall_name);
			if (syscall_nr == __NR_SCMP_ERROR) {
				ruri_error("Failed to resolve syscall: %s\n", syscall_name);
			}
			return seccomp_rule_add(*ctx, action, syscall_nr, 0);
		}
	}
	return -1;
}
#endif
// Setup seccomp filter rule, with libseccomp.
void ruri_setup_seccomp(const struct RURI_CONTAINER *_Nonnull container)
{
#ifndef DISABLE_LIBSECCOMP
	/*
	 * Based on docker's default seccomp profile.
	 * This is a blacklist profile.
	 * NOTE: This profile is not fully tested.
	 */
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	// Deny user-defined syscalls.
	for (int i = 0; container->seccomp_denied_syscall[i] != NULL; i++) {
		int syscall_nr = seccomp_syscall_resolve_name(container->seccomp_denied_syscall[i]);
		if (syscall_nr == __NR_SCMP_ERROR) {
			if (ruri_resolve_seccomp_errno(container->seccomp_denied_syscall[i], &ctx) != 0) {
				ruri_error("Failed to resolve syscall: %s\n", container->seccomp_denied_syscall[i]);
			}
		} else {
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, syscall_nr, 0);
		}
	}
	// For non-root user, pass capability checks.
	bool not_root_user = false;
	if (container->user != NULL) {
		if (strcmp(container->user, "root") != 0 && strcmp(container->user, "0") != 0) {
			not_root_user = true;
		}
	}
	// Default rules.
	if (container->enable_default_seccomp) {
#ifndef DISABLE_LIBCAP
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PACCT) || not_root_user) {
			// acct() is used for process accounting, which is not needed in most cases and can be abused for DoS attacks.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(acct), 0);
		}
		// Disallow AF_ALG.
		// See Copy-Fail.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_ALG));
		// Disallow AF_RDS.
		// See pintheft.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RDS));
		// Disallow AF_RXRPC.
		// See DirtyFrag.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RXRPC));
		// Disallow NETLINK_XFRM for AF_NETLINK.
		// See DirtyFrag.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 2, SCMP_CMP(0, SCMP_CMP_EQ, AF_NETLINK), SCMP_CMP(2, SCMP_CMP_EQ, NETLINK_XFRM));
		//
		// Anyway, go ahead and disallow these unused socket families.
		//
		// Disallow AF_AX25.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_AX25));
		// Disallow AF_IPX.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IPX));
		// Disallow AF_APPLETALK.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_APPLETALK));
		// Disallow AF_X25.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_X25));
		// Disallow AF_DECnet.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_DECnet));
		// Disallow AF_PPPOX.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PPPOX));
		// Disallow AF_LLC.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_LLC));
		// Disallow AF_IB.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IB));
		// Disallow AF_MPLS.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_MPLS));
		// Disallow AF_CAN.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_CAN));
		// Disallow AF_TIPC.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_TIPC));
		// Disallow AF_BLUETOOTH.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_BLUETOOTH));
		// Disallow AF_KCM.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KCM));
		// Disallow AF_KEY.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KEY));
		// Disallow AF_PACKET.
		if (ruri_is_in_caplist(container->drop_caplist, CAP_NET_RAW) || not_root_user) {
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PACKET));
		}
		// Disallow IORING_REGISTER_BUFFERS and IORING_REGISTER_CLONE_BUFFERS.
		// ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 1, SCMP_CMP(1, SCMP_CMP_EQ, IORING_REGISTER_BUFFERS));
		// ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 1, SCMP_CMP(1, SCMP_CMP_EQ, IORING_REGISTER_CLONE_BUFFERS));
		// Fully ban io_uring
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_enter), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_setup), 0);
		// add_key(2) and keyctl(2) are used for kernel key management.
		// See CVE-2016-0728, CVE-2017-15951.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);
		// Ban eBPF, it should be used outside of container, not inside.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_ADMIN) || not_root_user) {
			// Fix `TIODSTI should be a privileged operation`.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI));
			// lookup_dcookie(2) is used to look up the path of a file descriptor.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(lookup_dcookie), 0);
			// mount(2), as we all know.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
			// quotactl(2) is used to manage disk quotas, which is not needed in most cases and can be abused for DoS attacks.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(quotactl), 0);
			// Why you setup swap in container? Bro so crazy.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapon), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapoff), 0);
			// setns(2) and unshare(2) can be used to escape container in many cases.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setns), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0);
			// clone(2) can have the same effect as unshare(2), we deny it.
			unsigned int clone_flags[] = { CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS };
			for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
				// For s390, they use arg1, not arg0.
				if (seccomp_arch_native() == SCMP_ARCH_S390) {
					ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i]));
				} else {
					ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i]));
				}
			}
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
			// Why you run 8086 vm in container? Weird.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(vm86), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(vm86old), 0);
		}
		// It's anyway so weird to change system time in container.
		// Maybe in time ns it's okey?
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_adjtime), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_settime), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(settimeofday), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(stime), 0);
		// Hey, what are you doing? .ko files should on your host, not in container.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(create_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
		// Deprecated syscalls, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(get_kernel_syms), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_NICE) || not_root_user) {
			// Seems not very dangerous, so just follow CAP_SYS_NICE.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(get_mempolicy), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mbind), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(set_mempolicy), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setscheduler), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setattr), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_pages), 0);
		}
		// Do not touch any hardware I/O ports in container, it's really dangerous and not needed.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(ioperm), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(iopl), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_PTRACE) || not_root_user) {
			// kcmp(2) can be used for side channel attacks, we deny it for non-root users.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0);
			// process_vm_readv(2) and process_vm_writev(2) can be used to read/write another process's memory, which is very dangerous.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
			// ptrace(2) can be used to trace another process, which is very dangerous.
			// But, as strace and gdb need ptrace, we just deny it for non-root users, and allow it for root users.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
			// perf_event_open(2) can be used to monitor another process's performance, can be used for side channel attacks.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(perf_event_open), 0);
		}
		// Why you need to load kernel in container? Anyway, no.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
		// Meow????? Do not. It should be used outside of container, not inside.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(nfsservctl), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_DAC_READ_SEARCH) || not_root_user) {
			// open_by_handle_at(2) can be used to access files outside of their intended scope, which is very dangerous.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(open_by_handle_at), 0);
		}
		// wine/box86 needs personality syscall.
		// deny ADDR_NO_RANDOMIZE.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_NO_RANDOMIZE, ADDR_NO_RANDOMIZE));
		// deny READ_IMPLIES_EXEC.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, READ_IMPLIES_EXEC, READ_IMPLIES_EXEC));
		// deny MMAP_PAGE_ZERO.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, MMAP_PAGE_ZERO, MMAP_PAGE_ZERO));
		// deny ADDR_COMPAT_LAYOUT.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_COMPAT_LAYOUT, ADDR_COMPAT_LAYOUT));
		// deny ADDR_LIMIT_32BIT.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_LIMIT_32BIT, ADDR_LIMIT_32BIT));
		// deny ADDR_LIMIT_3GB.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_LIMIT_3GB, ADDR_LIMIT_3GB));
		// deny PER_SVR4.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, PER_MASK, PER_SVR4));
		// deny PER_UW7.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, PER_MASK, PER_UW7));
		// I think I just called pivot_root() for you bro.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(query_module), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(sysfs), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(_sysctl), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(uselib), 0);
		// userfaultfd(2) can be used for UAF, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(userfaultfd), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(ustat), 0);
		if (ruri_is_in_caplist(container->drop_caplist, CAP_SYS_CHROOT) || not_root_user) {
			// You don't need chroot(2) in container.
			// Can be used to escape container in some cases, and it's really dangerous.
			// But, as systemctl even tries this, we just deny it as EPERM.
			ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0);
		}
#else
		// acct() is used for process accounting, which is not needed in most cases and can be abused for DoS attacks.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(acct), 0);
		// Disallow AF_ALG.
		// See Copy-Fail.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_ALG));
		// Disallow AF_RDS.
		// See pintheft.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RDS));
		// Disallow AF_RXRPC.
		// See DirtyFrag.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_RXRPC));
		// Disallow NETLINK_XFRM for AF_NETLINK.
		// See DirtyFrag.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 2, SCMP_CMP(0, SCMP_CMP_EQ, AF_NETLINK), SCMP_CMP(2, SCMP_CMP_EQ, NETLINK_XFRM));
		//
		// Anyway, go ahead and disallow these unused socket families.
		//
		// Disallow AF_AX25.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_AX25));
		// Disallow AF_IPX.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IPX));
		// Disallow AF_APPLETALK.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_APPLETALK));
		// Disallow AF_X25.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_X25));
		// Disallow AF_DECnet.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_DECnet));
		// Disallow AF_PPPOX.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PPPOX));
		// Disallow AF_LLC.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_LLC));
		// Disallow AF_IB.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_IB));
		// Disallow AF_MPLS.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_MPLS));
		// Disallow AF_CAN.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_CAN));
		// Disallow AF_TIPC.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_TIPC));
		// Disallow AF_BLUETOOTH.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_BLUETOOTH));
		// Disallow AF_KCM.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KCM));
		// Disallow AF_KEY.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_KEY));
		// Disallow AF_PACKET.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_PACKET));
		// Disallow IORING_REGISTER_BUFFERS and IORING_REGISTER_CLONE_BUFFERS.
		// ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 1, SCMP_CMP(1, SCMP_CMP_EQ, IORING_REGISTER_BUFFERS));
		// ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 1, SCMP_CMP(1, SCMP_CMP_EQ, IORING_REGISTER_CLONE_BUFFERS));
		// Fully ban io_uring
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_register), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_enter), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_uring_setup), 0);
		// add_key(2) and keyctl(2) are used for kernel key management.
		// See CVE-2016-0728, CVE-2017-15951.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);
		// Ban eBPF, it should be used outside of container, not inside.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);
		// Fix `TIODSTI should be a privileged operation`.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI));
		// lookup_dcookie(2) is used to look up the path of a file descriptor.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(lookup_dcookie), 0);
		// mount(2), as we all know.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
		// quotactl(2) is used to manage disk quotas, which is not needed in most cases and can be abused for DoS attacks.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(quotactl), 0);
		// Why you setup swap in container? Bro so crazy.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapon), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapoff), 0);
		// setns(2) and unshare(2) can be used to escape container in many cases.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setns), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0);
		// clone(2) can have the same effect as unshare(2), we deny it.
		unsigned int clone_flags[] = { CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS };
		for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
			// For s390, they use arg1, not arg0.
			if (seccomp_arch_native() == SCMP_ARCH_S390) {
				ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i]));
			} else {
				ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, clone_flags[i], clone_flags[i]));
			}
		}
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
		// Why you run 8086 vm in container? Weird.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(vm86), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(vm86old), 0);
		// It's anyway so weird to change system time in container.
		// Maybe in time ns it's okey?
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_adjtime), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_settime), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(settimeofday), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(stime), 0);
		// Hey, what are you doing? .ko files should on your host, not in container.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(create_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
		// Deprecated syscalls, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(get_kernel_syms), 0);
		// Seems not very dangerous, so just follow CAP_SYS_NICE.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(get_mempolicy), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mbind), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(set_mempolicy), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setscheduler), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sched_setattr), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(move_pages), 0);
		// Do not touch any hardware I/O ports in container, it's really dangerous and not needed.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(ioperm), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(iopl), 0);
		// kcmp(2) can be used for side channel attacks, we deny it for non-root users.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0);
		// process_vm_readv(2) and process_vm_writev(2) can be used to read/write another process's memory, which is very dangerous.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
		// ptrace(2) can be used to trace another process, which is very dangerous.
		// But, as strace and gdb need ptrace, we just deny it for non-root users, and allow it for root users.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
		// perf_event_open(2) can be used to monitor another process's performance, can be used for side channel attacks.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(perf_event_open), 0);
		// Why you need to load kernel in container? Anyway, no.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_file_load), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
		// Meow????? Do not. It should be used outside of container, not inside.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(nfsservctl), 0);
		// open_by_handle_at(2) can be used to access files outside of their intended scope, which is very dangerous.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(open_by_handle_at), 0);
		// wine/box86 needs personality syscall.
		// deny ADDR_NO_RANDOMIZE.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_NO_RANDOMIZE, ADDR_NO_RANDOMIZE));
		// deny READ_IMPLIES_EXEC.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, READ_IMPLIES_EXEC, READ_IMPLIES_EXEC));
		// deny MMAP_PAGE_ZERO.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, MMAP_PAGE_ZERO, MMAP_PAGE_ZERO));
		// deny ADDR_COMPAT_LAYOUT.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_COMPAT_LAYOUT, ADDR_COMPAT_LAYOUT));
		// deny ADDR_LIMIT_32BIT.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_LIMIT_32BIT, ADDR_LIMIT_32BIT));
		// deny ADDR_LIMIT_3GB.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ADDR_LIMIT_3GB, ADDR_LIMIT_3GB));
		// deny PER_SVR4.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, PER_MASK, PER_SVR4));
		// deny PER_UW7.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1, SCMP_CMP(0, SCMP_CMP_MASKED_EQ, PER_MASK, PER_UW7));
		// I think I just called pivot_root() for you bro.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(query_module), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(sysfs), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(_sysctl), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(uselib), 0);
		// userfaultfd(2) can be used for UAF, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(userfaultfd), 0);
		// Deprecated syscall, we kill it directly.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_KILL, SCMP_SYS(ustat), 0);
		// You don't need chroot(2) in container.
		// Can be used to escape container in some cases, and it's really dangerous.
		// But, as systemctl even tries this, we just deny it as EPERM.
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0);
#endif
	}
	if (container->systemd_mode) {
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 1, SCMP_CMP(5, SCMP_CMP_MASKED_EQ, MNT_FORCE, MNT_FORCE));
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0);
		ruri_seccomp_rule_add(container, ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0);
	}
	// Disable no_new_privs bit by default.
	seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);
	// Load seccomp rules.
	if (seccomp_load(ctx) != 0) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{yellow}Warning: failed to load seccomp filter QwQ{clear}\n");
	}
	ruri_log("{base}Seccomp filter loaded\n");
#endif
}
