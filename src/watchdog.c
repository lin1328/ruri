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
			// Timeout reached, kill the container process.
			if ((now_ns - start_ns) >= (long long)(container->timeout * 1000000000LL)) {
				// This will exit pid_file daemon.
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
int ruri_setup_pid_file_daemon(struct RURI_CONTAINER *_Nonnull container)
{
	// Use SOCK_SEQPACKET to create a socket pair for pid file, so we can read the pid from it without worrying about buffering.
	int pid_pipe[2] = { -1, -1 };
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pid_pipe) < 0) {
		ruri_warning("{red}Warning: failed to create socket pair for pid file, pid file will not be updated QwQ\n");
	}
	int pid_file_fd = pid_pipe[0];
	ruri_pid_file_fd(pid_pipe[1]);
	signal(SIGPIPE, SIG_IGN);
	// fork() twice then watch pid_file_fd, and write content to pidfile.
	pid_t pid1 = fork();
	if (pid1 > 0) {
		// Parent process, wait for child to exit.
		waitpid(pid1, NULL, 0);
	} else {
		// First child process, fork again.
		pid_t pid2 = fork();
		if (pid2 > 0) {
			exit(EXIT_SUCCESS);
		} else {
			ruri_proc_mark(RURI_DAEMON);
			// Redirect output to /dev/null.
			int dev_null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
			dup2(dev_null_fd, STDOUT_FILENO);
			dup2(dev_null_fd, STDERR_FILENO);
			close(dev_null_fd);
			// Close the write end of the pipe in the child process, we only need to read from it.
			close(pid_pipe[1]);
			signal(SIGPIPE, SIG_IGN);
			// read pid from pid_file_fd and write to pidfile.
			int file_fd = -1;
			if (container->pid_file == NULL) {
				file_fd = open("/dev/null", O_RDWR);
			} else {
				file_fd = open(container->pid_file, O_CREAT | O_CLOEXEC | O_RDWR, S_IRUSR | S_IWUSR);
			}
			if (file_fd < 0) {
				exit(EXIT_FAILURE);
			}
			ftruncate(file_fd, 0);
			lseek(file_fd, 0, SEEK_SET);
			char buf[256] = { 0 };
			// Write current time to pid file, so we can detect if the container is running by checking if the pid file is updated.
			// Get current time in ns.
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			long long now_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
			snprintf(buf, sizeof(buf), "RURI_INIT_%lld\n", now_ns);
			write(file_fd, buf, strlen(buf));
			while (1) {
				memset(buf, 0, sizeof(buf));
				ssize_t n = read(pid_file_fd, buf, sizeof(buf) - 1);
				if (n > 0) {
					buf[n] = '\0';
					// only 0-9,a-z,A-Z and _ are allowed in the pid file, for safety.
					for (ssize_t i = 0; i < n; i++) {
						if (!((buf[i] >= '0' && buf[i] <= '9') || (buf[i] >= 'a' && buf[i] <= 'z') || (buf[i] >= 'A' && buf[i] <= 'Z') || buf[i] == '_' || buf[i] == '\n')) {
							memset(buf, 0, sizeof(buf));
							continue;
						}
					}
					ftruncate(file_fd, 0);
					lseek(file_fd, 0, SEEK_SET);
					write(file_fd, buf, n);
					fsync(file_fd);
					// If we got RURI_PANIC_*, exit now.
					if (strncmp(buf, "RURI_PANIC_", strlen("RURI_PANIC_")) == 0) {
						// For timeout panic, just exit.
						if (strncmp(buf, "RURI_PANIC_TIMEOUT", strlen("RURI_PANIC_TIMEOUT")) == 0) {
							exit(EXIT_FAILURE);
						}
						if (container->auto_umount || container->auto_umount_on_panic) {
							// Sleep 0.5s.
							usleep(500000);
							ruri_umount_container(container->container_dir);
						}
						exit(EXIT_FAILURE);
					}
				} else if (n == 0) {
					// EOF, the other side has closed the connection, exit.
					if (container->auto_umount) {
						// Sleep 0.5s.
						usleep(500000);
						ruri_umount_container(container->container_dir);
					}
					exit(EXIT_SUCCESS);
				} else {
					// Error, maybe EINTR, try again.
					if (errno == EINTR) {
						continue;
					}
					// Other errors, exit.
					if (container->auto_umount) {
						// Sleep 0.5s.
						usleep(500000);
						ruri_umount_container(container->container_dir);
					}
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	close(pid_pipe[0]);
	return pid_file_fd;
}