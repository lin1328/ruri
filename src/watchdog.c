// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2026 Moe-hacker
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
void ruri_setup_timeout_watchdog(const struct RURI_CONTAINER *_Nonnull container)
{
	// Get pid to watch.
	pid_t to_watch = getpid();
	// fork() twice.
	pid_t timeout_pid1 = fork();
	if (timeout_pid1 > 0) {
		// Parent process, wait for child to exit.
		waitpid(timeout_pid1, NULL, 0);
	} else {
		pid_t timeout_pid = fork();
		if (timeout_pid < 0) {
			ruri_error("{red}Failed to fork for timeout watchdog QwQ\n");
		}
		if (timeout_pid > 0) {
			exit(0);
		}
		// Redirect output to /dev/null.
		int dev_null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		dup2(dev_null_fd, STDOUT_FILENO);
		dup2(dev_null_fd, STDERR_FILENO);
		close(dev_null_fd);
		ruri_proc_mark(RURI_DAEMON);
		// Get current time in ns.
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		long long start_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
		while (1) {
			// If pid died, exit.
			if (kill(to_watch, 0) < 0) {
				exit(0);
			}
			// Check for timeout.
			clock_gettime(CLOCK_MONOTONIC, &ts);
			long long now_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
			if ((now_ns - start_ns) >= (long long)(container->timeout * 1000000000LL)) {
				// Timeout reached, kill the container process.
				ruri_pid_file_write(RURI_PID_FILE_PANIC_TIMEOUT, 0);
				usleep(100000); // Sleep 0.1s to wait for the pid file to be updated.
				kill(to_watch, SIGKILL);
				usleep(100000); // Sleep 0.1s to wait for the process to be killed.
				if (container->auto_umount_on_panic) {
					// Sleep 0.5s.
					usleep(500000);
					ruri_umount_container(container->container_dir);
				}
				exit(EXIT_FAILURE);
			}
			// Sleep 1/10 of timeout.
			usleep((container->timeout * 100000) / 10);
		}
		exit(EXIT_SUCCESS);
	}
}