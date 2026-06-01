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
#include "../src/include/ruri.h"
// Create a memfd in parent process, and pass the file descriptor to child process through command line argument.
// To test if we can get pid_file from memfd, so no disk file is needed.
int main(int argc, char *argv[])
{
	int fd = memfd_create("test", 0);
	fchmod(fd, 0777);
	if (fd == -1) {
		perror("memfd_create");
		return 1;
	}
	char proc_fs_fd_path[PATH_MAX];
	snprintf(proc_fs_fd_path, sizeof(proc_fs_fd_path), "/proc/%d/fd/%d", getpid(), fd);
	pid_t fork_pid = fork();
	if (fork_pid == -1) {
		perror("fork");
		return 1;
	} else if (fork_pid == 0) {
		// Child process
		char *argv_new[argc + 2];
		argv_new[0] = "ruri"; // Program name
		argv_new[1] = "--pid-file"; // Option flag
		argv_new[2] = proc_fs_fd_path; // Path to the memfd file descriptor
		for (int i = 1; i < argc; i++) {
			argv_new[i + 2] = argv[i]; // Copy original arguments
		}
		argv_new[argc + 2] = NULL; // Null-terminate the argument list
		execv("./ruri", argv_new); // Execute the new program
		perror("execv"); // If execv returns, it must have failed
		return 1;
	} else {
		wait(NULL); // Wait for the child process to finish
		char buffer[256];
		ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
		if (bytesRead == -1) {
			perror("read");
			return 1;
		}
		buffer[bytesRead] = '\0'; // Null-terminate the buffer
		printf("Data read from memfd: \n///\n%s///\n", buffer);
	}
}