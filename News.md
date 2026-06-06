v3.9.4 is a huge release with many new features and improvements. So rc-1 is out for testing.   
  * Skip setgroups() when user is root and cannot parse /etc/group and /etc/passwd.
  * Auto detect device major and minor number when major is set to 0 in `--char-dev` option.
  * Auto add `cap_` prefix for capability name in `--cap-drop` and `--cap-add` option.
  * Use host cgroup path for cgroup setup.
  * Use cgroup for kill/ps unshare container if available.
  * Experimentally support `--systemd` with `--even-unstable` option, but it may not work as expected.
  * Add `--strict-mode` option to make ruri exit immediately when any error.
  * Add `--pid-file` option to write the PID of the container to a file.
  * Experimentally support `--stat` option to read pidfile.
  * Add `--auto-umount` option to automatically umount the container when it exits.
  * Experimentally support `--umount-on-panic` option to automatically umount the container when it exits.
  * Add `--health-check` option for health check process.
  * Add `--timeout` option to automatically kill the process after the specified time.
  * Experimentally support `--fork-as-init` option to make ruri fork() as init process before exec() in container.
  * Rewrite default seccomp profile, make it more useable, and act for recent 0day vulnerabilities.
  * Kang moby's whitelist seccomp profile for `--enable-seccomp-whitelist`.
  * Migrate libk2v to libk2v3.
  * Refactored build system.
  * Ruri now has Super Neko Powers!