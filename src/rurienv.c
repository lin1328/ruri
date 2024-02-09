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
// Check if the running pid is ruri.
static bool is_ruri_pid(pid_t pid)
{
	char stat_path[PATH_MAX] = { '\0' };
	sprintf(stat_path, "/proc/%d/stat", pid);
	int fd = open(stat_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	char buf[4096] = { '\0' };
	char name[1024] = { '\0' };
	read(fd, buf, sizeof(buf));
	for (int i = 0; true; i++) {
		if (buf[i] == '(') {
			for (int j = 1; true; j++) {
				if (buf[i + j] == ')') {
					break;
				}
				name[j - 1] = buf[i + j];
				name[j] = '\0';
			}
			break;
		}
	}
	if (strcmp(name, "ruri") == 0) {
		return true;
	}
	return false;
}
// Build container_info struct.
static struct CONTAINER_INFO *build_container_info(const struct CONTAINER *container)
{
	struct CONTAINER_INFO *info = (struct CONTAINER_INFO *)malloc(sizeof(struct CONTAINER_INFO));
	for (int i = 0; i <= CAP_LAST_CAP + 1; i++) {
		info->drop_caplist[i] = container->drop_caplist[i];
	}
	info->no_new_privs = container->no_new_privs;
	info->enable_seccomp = container->no_new_privs;
	info->ns_pid = container->ns_pid;
	for (int i = 0; true; i++) {
		if (container->extra_mountpoint[i] == NULL) {
			info->extra_mountpoint[i][0] = '\0';
			break;
		}
		strcpy(info->extra_mountpoint[i], container->extra_mountpoint[i]);
	}
	for (int i = 0; true; i++) {
		if (container->env[i] == NULL) {
			info->env[i][0] = '\0';
			break;
		}
		strcpy(info->env[i], container->env[i]);
	}
	return info;
}
// Store container info.
void store_info(const struct CONTAINER *container)
{
	struct CONTAINER_INFO *info = build_container_info(container);
	char file[PATH_MAX] = { '\0' };
	sprintf(file, "%s/.rurienv", container->container_dir);
	unlink(file);
	remove(file);
	FILE *fp = fopen(file, "w+");
	fwrite(info, sizeof(struct CONTAINER_INFO), 1, fp);
	fclose(fp);
	free(info);
}
// Read .rurienv file.
struct CONTAINER *read_info(struct CONTAINER *container, const char *container_dir)
{
	struct CONTAINER_INFO *info = (struct CONTAINER_INFO *)malloc(sizeof(struct CONTAINER_INFO));
	char file[PATH_MAX] = { '\0' };
	sprintf(file, "%s/.rurienv", container_dir);
	FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		free(info);
		return container;
	}
	fread(info, sizeof(struct CONTAINER_INFO), 1, fp);
	if (container == NULL) {
		container = (struct CONTAINER *)malloc(sizeof(struct CONTAINER));
		for (int i = 0; true; i++) {
			if (info->extra_mountpoint[i][0] == '\0') {
				container->extra_mountpoint[i] = NULL;
				container->extra_mountpoint[i + 1] = NULL;
				break;
			}
			container->extra_mountpoint[i] = strdup(info->extra_mountpoint[i]);
		}

		fclose(fp);
		free(info);
		return container;
	}
	if (container->enable_unshare && !is_ruri_pid(info->ns_pid)) {
		remove(file);
		return container;
	}
	for (int i = 0; i <= CAP_LAST_CAP + 1; i++) {
		container->drop_caplist[i] = info->drop_caplist[i];
	}
	container->no_new_privs = info->no_new_privs;
	container->enable_seccomp = info->no_new_privs;
	container->ns_pid = info->ns_pid;
	int j = 0;
	for (int i = 0; true; i++) {
		if (container->env[i] == NULL) {
			j = i;
			break;
		}
	}
	for (int i = 0; true; i++) {
		if (info->env[i][0] == '\0') {
			container->env[j] = NULL;
			break;
		}
		container->env[j] = strdup(info->env[i]);
		j++;
	}
	fclose(fp);
	free(info);
	return container;
}