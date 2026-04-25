// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2022-2026 Moe-hacker
 *  and partially...  2026 BarryLhm
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
 * This file provides functions to set cgoup limits for container.
 * ${container_id} is set by the time creating the container,
 * And it will be unified by .rurienv file.
 *
 * TODO:
 * Add more cgroups support.
 */
// Returns -1 for malformed size
// Returns -2 for too large
static ssize_t humansize_to_bytes(const char *_Nonnull human)
{
	char *endptr = NULL;
	errno = 0;
	long long ret = strtoll(human, &endptr, 10);
	// these become too long after formatted
	// clang-format off
	if (errno == ERANGE) return -2;
	if (endptr == human || ret < 0) return -1; // no number or negative
	if (!*endptr) { if (ret > SSIZE_MAX) return -2;
	} else {
		if (*(endptr + 1)) return -1; // invalid unit
		switch (*endptr) {
		case 'k': case 'K': if (ret > SSIZE_MAX / 1024) return -2; ret *= 1024; break;
		case 'm': case 'M': if (ret > SSIZE_MAX / 1024 / 1024) return -2; ret *= 1024 * 1024; break;
		case 'g': case 'G': if (ret > SSIZE_MAX / 1024 / 1024 / 1024) return -2; ret *= 1024 * 1024 * 1024; break;
		default: return -1; // invalid unit
		}
	}
	// clang-format on
	return ret;
}
// Returns 1 for failed open() and 2 for failed write().
// Only write control files!!
static int open_and_write(const char *file, const char *value)
{
	// Open and write control file
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		return 1;
	}
	if (write(fd, value, strlen(value)) < 0) {
		close(fd);
		return 2;
	};
	close(fd);
	return 0;
}
/*
 *                                          _
 *   ___ __ _ _ __ ___  _   _ _ __   __   _/ |
 *  / __/ _` | '__/ _ \| | | | '_ \  \ \ / / |
 * | (_| (_| | | | (_) | |_| | |_) |  \ V /| |
 *  \___\__, |_|  \___/ \__,_| .__/    \_/ |_|
 *      |___/                |_|
 */
static bool is_cgroup_v1_mounted()
{
	/*
	 * Use statfs() to check if cgroup v1 is mounted.
	 * Return true if cgroup v1 is mounted.
	 */
	struct statfs buf;
	if (statfs("/sys/fs/cgroup", &buf) < 0) {
		return false;
	}
	return buf.f_type == TMPFS_MAGIC;
}
// Returns the same as open_and_write().
static int cgroup_v1_attach(const struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull controller)
{
	pid_t pid = getpid();
	char buf[256] = "";
	char cgroup_path[PATH_MAX] = "";
	sprintf(cgroup_path, "/sys/fs/cgroup/%s/ruri/%d", controller, container->container_id);
	mkdir(cgroup_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char cgroup_procs_path[PATH_MAX] = "";
	sprintf(cgroup_procs_path, "/sys/fs/cgroup/%s/ruri/%d/cgroup.procs", controller, container->container_id);
	// Add pid to container_id memory cgroup.
	sprintf(buf, "%d\n", pid);
	return open_and_write(cgroup_procs_path, buf);
}
static void set_cgroup_v1(const struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull controller)
{
	/*
	 * Set cgroupv1 _any_ controller limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	char cgroup_master_path[PATH_MAX] = "";
	sprintf(cgroup_master_path, "/sys/fs/cgroup/%s/ruri", controller);
	if (mkdir(cgroup_master_path, S_IRUSR | S_IWUSR) && errno != EEXIST) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to create cgroup node\n");
		return;
	}
	char cgroup_node_path[PATH_MAX] = "";
	sprintf(cgroup_node_path, "/sys/fs/cgroup/%s/ruri/%d", controller, container->container_id);
	mkdir(cgroup_node_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char *controller_name = "!!!internal error!!!";
	if (!strcmp(controller, "memory")) {
		if (!container->memory) {
			return;
		}
		controller_name = "memory";
		// Set memory limit.
		char memory_cgroup_limit_path[PATH_MAX] = "";
		sprintf(memory_cgroup_limit_path, "/sys/fs/cgroup/memory/ruri/%d/memory.limit_in_bytes", container->container_id);
		ssize_t memory = humansize_to_bytes(container->memory);
		switch (memory) {
		case -1:
			if (!container->no_warnings) {
				ruri_error("Memory format error, only ^[1-9]+[kKmMgG]$ is supported\n");
			}
			return;
		case -2:
			if (!container->no_warnings) {
				ruri_error("Memory value too big to current platform\n");
			}
			return;
		}
		char buf[256] = "";
		sprintf(buf, "%zd\n", memory);
		if (open_and_write(memory_cgroup_limit_path, buf)) {
			goto fail;
		}
		char memory_cgroup_oom_path[PATH_MAX] = "";
		sprintf(memory_cgroup_oom_path, "/sys/fs/cgroup/memory/ruri/%d/memory.oom_control", container->container_id);
		if (open_and_write(memory_cgroup_oom_path, "1\n")) {
			goto fail;
		}
	} else if (!strcmp(controller, "cpu")) {
		if (!container->cpupercent) {
			return;
		}
		controller_name = "cpupercent";
		// Set cpu limit.
		char cpu_cgroup_quota_path[PATH_MAX] = "";
		sprintf(cpu_cgroup_quota_path, "/sys/fs/cgroup/cpu/ruri/%d/cpu.cfs_quota_us", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d\n", container->cpupercent * 1000);
		if (open_and_write(cpu_cgroup_quota_path, buf)) {
			goto fail;
		}
		char cpu_cgroup_period_path[PATH_MAX] = "";
		sprintf(cpu_cgroup_period_path, "/sys/fs/cgroup/cpu/ruri/%d/cpu.cfs_period_us", container->container_id);
		sprintf(buf, "%d\n", 100000);
		if (open_and_write(cpu_cgroup_period_path, buf)) {
			goto fail;
		}

	} else if (!strcmp(controller, "cpuset")) {
		if (!container->cpuset) {
			return;
		}
		controller_name = "cpuset";
		// Set cpuset limit.
		char cpuset_cgroup_mems_path[PATH_MAX] = "";
		sprintf(cpuset_cgroup_mems_path, "/sys/fs/cgroup/cpuset/ruri/%d/cpuset.mems", container->container_id);
		if (open_and_write(cpuset_cgroup_mems_path, "0\n")) {
			goto fail;
		}
		char cpuset_cgroup_cpus_path[PATH_MAX] = "";
		sprintf(cpuset_cgroup_cpus_path, "/sys/fs/cgroup/cpuset/ruri/%d/cpuset.cpus", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->cpuset);
		if (open_and_write(cpuset_cgroup_cpus_path, buf)) {
			goto fail;
		}
	} else {
		controller_name = "!!!internal error!!!";
		goto fail;
	}
	if (cgroup_v1_attach(container, controller)) {
		goto fail;
	}
fail:
	ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v1 %s limit\n", controller_name);
}
/*
 *                                          ____
 *   ___ __ _ _ __ ___  _   _ _ __   __   _|___ \
 *  / __/ _` | '__/ _ \| | | | '_ \  \ \ / / __) |
 * | (_| (_| | | | (_) | |_| | |_) |  \ V / / __/
 *  \___\__, |_|  \___/ \__,_| .__/    \_/ |_____|
 *      |___/                |_|
 */
static bool is_cgroup_v2_mounted()
{
	/*
	 * Use statfs() to check if cgroup v2 is mounted.
	 * Return true if cgroup v2 is mounted.
	 */
	struct statfs buf;
	if (statfs("/sys/fs/cgroup", &buf) < 0) {
		return false;
	}
	return buf.f_type == CGROUP2_SUPER_MAGIC;
}
// Returns 1 for failure.
static int cgroup_v2_attach(const struct RURI_CONTAINER *_Nonnull container)
{
	pid_t pid = getpid();
	char buf[256] = "";
	char cgroup_path[PATH_MAX] = "";
	sprintf(cgroup_path, "/sys/fs/cgroup/ruri/%d", container->container_id);
	usleep(200);
	// Add pid to container_id cgroup.
	char cgroup_procs_path[PATH_MAX] = "";
	sprintf(cgroup_procs_path, "/sys/fs/cgroup/ruri/%d/cgroup.procs", container->container_id);
	sprintf(buf, "%d\n", pid);
	if (open_and_write(cgroup_procs_path, buf)) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to attach cgroup\n");
		// Report failure for apifs cleanup
		return 1;
	}
	return 0;
}
static void set_cgroup_v2(const struct RURI_CONTAINER *_Nonnull container, const char *_Nonnull controller)
{
	/*
	 * Set cgroupv2 _any_ controller limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	char cgroup_node_path[PATH_MAX] = "";
	sprintf(cgroup_node_path, "/sys/fs/cgroup/ruri/%d", container->container_id);
	mkdir(cgroup_node_path, S_IRUSR | S_IWUSR);
	usleep(200);
	char *controller_name = "!!!internal error!!!";
	if (strcmp(controller, "attach")) {
		if (mkdir("/sys/fs/cgroup/ruri", S_IRUSR | S_IWUSR) && errno != EEXIST) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to create cgroup node\n");
			return;
		}
		char buf[256] = "";
		sprintf(buf, "+%s\n", controller);
		open_and_write("/sys/fs/cgroup/cgroup.subtree_control", buf);
		if (open_and_write("/sys/fs/cgroup/ruri/cgroup.subtree_control", buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to enable controller %s\n", controller);
		}
	}
	if (!strcmp(controller, "attach")) {
		; // no controller to set, only attach the container
	} else if (!strcmp(controller, "memory")) {
		if (!container->memory) {
			return;
		}
		controller_name = "memory";
		// Set memory limit.
		char cgroup_memlimit_path[PATH_MAX] = "";
		sprintf(cgroup_memlimit_path, "/sys/fs/cgroup/ruri/%d/memory.high", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->memory);
		if (open_and_write(cgroup_memlimit_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
			return;
		}
		char cgroup_memlimit_path2[PATH_MAX] = "";
		sprintf(cgroup_memlimit_path2, "/sys/fs/cgroup/ruri/%d/memory.max", container->container_id);
		if (open_and_write(cgroup_memlimit_path2, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
			return;
		}
		char cgroup_oom_path[PATH_MAX] = "";
		sprintf(cgroup_oom_path, "/sys/fs/cgroup/ruri/%d/memory.oom.group", container->container_id);
		sprintf(buf, "1\n");
		if (open_and_write(cgroup_oom_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
			return;
		}
		ruri_log("{base}Set memory limit to %s\n", container->memory);
	} else if (!strcmp(controller, "cpu")) {
		if (container->cpupercent <= 0) {
			return;
		}
		controller_name = "cpupercent";
		// Set cpuset limit.
		char cgroup_cpu_path[PATH_MAX] = "";
		sprintf(cgroup_cpu_path, "/sys/fs/cgroup/ruri/%d/cpu.max", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%d 100000\n", container->cpupercent * 1000);
		if (open_and_write(cgroup_cpu_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
			return;
		}
	} else if (!strcmp(controller, "cpuset")) {
		if (!container->cpuset) {
			return;
		}
		controller_name = "cpuset";
		// Set cpuset limit.
		char cgroup_mems_path[PATH_MAX] = "";
		sprintf(cgroup_mems_path, "/sys/fs/cgroup/ruri/%d/cpuset.mems", container->container_id);
		if (open_and_write(cgroup_mems_path, "0\n")) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
			return;
		}
		char cgroup_cpuset_path[PATH_MAX] = "";
		sprintf(cgroup_cpuset_path, "/sys/fs/cgroup/ruri/%d/cpuset.cpus", container->container_id);
		char buf[256] = "";
		sprintf(buf, "%s\n", container->cpuset);
		if (open_and_write(cgroup_cpuset_path, buf)) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
			return;
		}
	} else {
		controller_name = "!!!unknown controller!!!";
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
	}
	// Add pid to container_id cgroup.
	if (cgroup_v2_attach(container)) {
		ruri_warn_on_error(1, 0, !container->no_warnings, "{red}Failed to set cgroup v2 %s limit\n", controller_name);
	}
}
/*
 *  ___       _             __
 * |_ _|_ __ | |_ ___ _ __ / _| __ _  ___ ___
 *  | || '_ \| __/ _ \ '__| |_ / _` |/ __/ _ \
 *  | || | | | ||  __/ |  |  _| (_| | (_|  __/
 * |___|_| |_|\__\___|_|  |_|  \__,_|\___\___|
 */
static void ruri_attach_cgroup_v2(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Attach process to cgroup v2.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 * Control file: /sys/fs/cgroup/ruri/${container_id}/cgroup.procs
	 */
	// Add pid to container_id cgroup.
	set_cgroup_v2(container, "attach");
}
static void ruri_cgroup_attach(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Attach process to cgroup.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	ruri_log("{blue}Attaching cgroup...\n");
	if (is_cgroup_v2_mounted()) {
		cgroup_v2_attach(container);
	} else if (is_cgroup_v1_mounted()) {
		cgroup_v1_attach(container, "memory");
		cgroup_v1_attach(container, "cpu");
		cgroup_v1_attach(container, "cpuset");
	} else {
		if (!container->no_warnings) {
			ruri_warning("{yellow}No cgroup support detected, skipping cgroup attach\n");
		}
	}
}
static bool cgroup_already_setup(int container_id)
{
	/*
	 * Check if cgroupv2 is already setup for the container.
	 * Return true if cgroup is already setup, false otherwise.
	 */
	if (is_cgroup_v2_mounted()) {
		char cgroup_path[PATH_MAX] = "";
		sprintf(cgroup_path, "/sys/fs/cgroup/ruri/%d", container_id);
		struct stat st;
		return stat(cgroup_path, &st) == 0 && S_ISDIR(st.st_mode);
	} else if (is_cgroup_v1_mounted()) {
		char memory_cgroup_path[PATH_MAX] = "";
		sprintf(memory_cgroup_path, "/sys/fs/cgroup/memory/ruri/%d", container_id);
		char cpu_cgroup_path[PATH_MAX] = "";
		sprintf(cpu_cgroup_path, "/sys/fs/cgroup/cpu/ruri/%d", container_id);
		char cpuset_cgroup_path[PATH_MAX] = "";
		sprintf(cpuset_cgroup_path, "/sys/fs/cgroup/cpuset/ruri/%d", container_id);
		return (access(memory_cgroup_path, F_OK) == 0 || access(cpu_cgroup_path, F_OK) == 0 || access(cpuset_cgroup_path, F_OK) == 0);
	}
	return false;
}
void ruri_set_limit(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Set cgroup controller limit.
	 * Nothing to return, only warnings to show if cgroup is not supported.
	 */
	if (!container->first_init || cgroup_already_setup(container->container_id)) {
		ruri_log("{blue}Container is already initialized, skipping cgroup limit setup.\n");
		ruri_cgroup_attach(container);
		return;
	} else {
		ruri_log("{blue}Setting cgroup limits for the first time...\n");
	}
	if (is_cgroup_v2_mounted()) {
		ruri_log("{blue}Cgroup v2 detected, setting limits with cgroup v2\n");
		set_cgroup_v2(container, "memory");
		set_cgroup_v2(container, "cpu");
		set_cgroup_v2(container, "cpuset");
	} else if (is_cgroup_v1_mounted()) {
		ruri_log("{blue}Cgroup v1 detected, setting limits with cgroup v1\n");
		set_cgroup_v1(container, "memory");
		set_cgroup_v1(container, "cpu");
		set_cgroup_v1(container, "cpuset");
	} else {
		if (container->memory || container->cpupercent > 0 || container->cpuset) {
			ruri_warn_on_error(1, 0, !container->no_warnings, "{red}No cgroup support detected, but cgroup limits are set\n");
		}
	}
}
// Returns 1 for failed try
int ruri_try_cgroup_kill(const struct RURI_CONTAINER *_Nonnull container)
{
	/*
	 * Kill all processes in corresponding cgroup v2 structure.
	 */
	if (!is_cgroup_v2_mounted()) {
		return 1;
	}
	usleep(200);
	char cgroup_kill_path[PATH_MAX] = "";
	sprintf(cgroup_kill_path, "/sys/fs/cgroup/ruri/%d/cgroup.kill", container->container_id);
	// Pid should be added beforehand.
	if (open_and_write(cgroup_kill_path, "1\n")) {
		goto fail;
	}
	char cgroup_systemd_path[PATH_MAX] = "";
	sprintf(cgroup_systemd_path, "/sys/fs/cgroup/ruri/%d/ruri-%d", container->container_id, container->container_id);
	rmdir(cgroup_systemd_path);
	usleep(2000);
	char cgroup_path[PATH_MAX] = "";
	sprintf(cgroup_path, "/sys/fs/cgroup/ruri/%d", container->container_id);
	rmdir(cgroup_path);
	return 0;
fail:
	if (!container->no_warnings) {
		ruri_warning("{yellow}trying to kill container with cgroup v2 failed\n");
	}
	return 1;
}
void container_ps_with_cgroup_v2(const struct RURI_CONTAINER *_Nonnull container)
{
	; // TODO
}
