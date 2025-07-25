# Initialization of container:
## Signal:
ruri will ignore SIGTTIN and SIGTTOU signals, so that the container can run in the background without being killed by these signals. This behavior cannot be overridden (#TODO: Maybe we can use environment variable to control this behavior in the future).

## The runtime files:
- /sys will be mounted as sysfs.
- /proc will be mounted as procfs.
- /dev will be mounted as tmpfs.
- /dev/pts will be mounted as devpts.
- /dev/shm will be mounted as tmpfs.

And, some path will be masked by ruri, unless `--unmask-dirs` is set, for details, see init_container() in src/chroot.c and init_rootless_container() in src/rootless.c.
## Noteable file changes:
- /.rurienv is managed by ruri, you should not try to edit or remove it.
- /qemu-ruri will be created by ruri if `-q` option is set, and the path of qemu binary is on host but not in container.
- /etc/mtab is a symlink to /proc/mounts, ruri will always create this file unless `-j` option is set.
