# Note:
BSD style usage is partially supported now, for example, you can use `-pW /root`, but `-W/root` is not allowed.    
# Usage:
```
ruri [OPTIONS]...
ruri [ARGS]... [CONTAINER_DIRECTORY]... [COMMAND [ARGS]...]
```
## Options:
```
-v, --version ...............................: Show version info
-V, --version-code ..........................: Show version code
-h, --help ..................................: Show helps
-H, --show-examples .........................: Show commandline examples
-P, --ps [container_dir/config] .............: Show process status of the container
```
These options will show the info.   
********************************************
```
-U, --umount [container_dir/config] .........: Umount a container
```
When running a container, ruri needs to mount some directories on it.         
And after running the container, you can use `-U` option to umount a container.          
This option both works with rootless and common container.      
Behavior note: This option will also kill all processes in the container.      
WARNING: Always do `sudo ruri -U /path/to/container` before you removing the container.      
***********************************
```
-C, --correct-config .................: Correct config.
```
Try to correct an incomplete config file.        
## Arguments:
Common ruri container should be run with sudo, with the new version, running ruri with a common user is also supported, you don't need `-r` option now, ruri will automatically detect.      
*****************************************
```
-D, --dump-config ...........................: Dump the config
```
ruri supports using config file, you can use `-D` option to dump current config of container.      
For example:      
```
ruri -D -k cap_sys_admin -d cap_sys_chroot ./t
```
This will dump the container config with `-k cap_sys_admin -d cap_sys_chroot`, so next time  you can just use the config instead of `-k cap_sys_admin -d cap_sys_chroot` argument.      
********************************************
```
-o, --output [config file] ..................: Set output file of `-D` option
```
This option is used for `-D` option, to save the config to a file.      
For example:
```
ruri -D -o test.conf -k cap_sys_admin -d cap_sys_chroot ./t
```
This will save config to test.conf.      
Behavior note: The config file will be a executable file with shebang line, so you can run it directly.    
For example:    
```
./test.conf
```
This will run the container with the config file.    
*****************************************
```
-c, --config [config] [args] [COMMAND [ARGS]]: Use config file
```
You can use `ruri -c config_file` to run a container with config file.      
For example:      
```
ruri -c test.conf
```
or:      
```
ruri -c test.conf -k cap_sys_admin /bin/su root -
```      
This will run container using test.conf.      
Behavior note: The config file has a hard size limit of 64K, this behavior can only be changed by modifying the source code.      
With the new version, you can also just execute the config file directly.      
***********************************************
```      
-a, --arch [arch] ...........................: Simulate architecture via binfmt_misc/QEMU
-q, --qemu-path [path] ......................: Specify the path of QEMU
```
These two arguments should be set at the same time.      
ruri supports to use qemu-user-static with the binfmt_misc feature of kernel to run cross-arch containers.      
`-q` option can use qemu path in host, it will be copied to /qemu-ruri in container.      
For example:      
```
ruri -q /usr/bin/qemu-x86_64-static -a x86_64 ./test-x86_64
```
But remember that do not use this feature to simulate host architecture.      
Note: This option need kernel support for binfmt_misc. And, the qemu binary must be statically linked or have all dependencies in the container.     
Behavior note: ruri will automatically copy the qemu binary to /qemu-ruri in container if it's out of the container.      
Note: This option is experimental, and may not work as expected. Report issues if you find any bugs.      
ruri use this feature to build itself with github actions, and it works well.      
Note: other interpreter might also work, but ruri only tested with QEMU.     
*******************************************************************
```
-u, --unshare ...............................: Enable unshare feature
```
ruri supports unshare container, but NET and USER namespace is currently not supported.        
Note: when PID 1 died in PID NS, the ns will be cleared, so all process in it will die.      
Note: This option need kernel support for namespaces, it will try to enable supported ns, but if failed, it will only show warnings.     
Behavior note: ruri will use pivot_root(2) instead of chroot(2) if unshare is enabled.      
For more info, refer man page of unshare(1), unshare(2), namespaces(7).      
*****************************************
```
-n, --no-new-privs ..........................: Set NO_NEW_PRIVS flag
```
This argument will set NO_NEW_PRIVS, commands like `sudo` will be unavailable for common user.      
For more info, refer man page of prctl(2) and PR_SET_NO_NEW_PRIVS.      
****************************************
```
-N, --no-rurienv ............................: Do not use .rurienv file
```
ruri will create /.rurienv in container to save container config by default, you can use this option to disable it.      
Behavior note: for unshare/rootless container, this option will print the PID, so that you can use it to join the namespace later.      
***************************************
```
-J, --join-ns [NS_PID].......................: Join ns using NS_PID.
```
If you use unshare/rootless container with -N option enabled, you can use this option to join its namespace.      
This will only work with `-uN` or `-rN` option enabled.      
For more info, refer man page of setns(2) and unshare(2).      
*********************************************
```
-s, --enable-seccomp ........................: Enable built-in Seccomp profile
```
ruri provides a built-in seccomp profile, but if you really need to use seccomp, you might need to edit src/seccomp.c with your own rules and recompile it.      
Note: This option need kernel support seccomp.      
Note: This option is experimental, and may not work as expected. Report issues if you find any bugs.      
For more info, refer man page of seccomp(2), prctl(2) and seccomp(3).      
****************************************
```
-p, --privileged ............................: Run privileged container
```
This argument will give all capabilities to container, but you can also use `-d` option to filter out capabilities you don't want to keep.      
For more info, refer man page of capabilities(7).     
*******************************************
```
-r, --rootless ..............................: Run rootless container
```
This option should be run with common user, so you can run rootless container with user ns.      
This option require `uidmap` package and user namespace support.      
Remember to setup /etc/subuid and /etc/subgid before running rootless container.      
Note: This option need user ns support, and need kernel to allow create user ns with common user.      
**NOTE** This option is already deprecated, you can just run ruri with common user now, it will automatically detect if it's rootless or not.      
For more info, refer man page of user_namespaces(7) and unshare(2).      
*********************************************
```
-k, --keep [cap] ............................: Keep the specified capability
-d, --drop [cap] ............................: Drop the specified capability
```
This two option can control the capability in container, cap can both be value or name.
For example, `-k cap_chown` have the same effect with `-k 0`.      
Behavior note: ruri will automatically drop some capabilities like CAP_SYS_ADMIN, CAP_SYS_CHROOT, etc. If you want to keep them, you can use `-k` option to keep them.  
For more info, refer man page of capabilities(7).      
**************************************************
```
-e, --env [env] [value] .....................: Set environment variables to its value
```
Behavior note: ruri clears all environment variables before launching the container for security and consistency. Therefore, LD_PRELOAD and other environment-based injection methods will not work. Also, they will not work for ruri itself.      
These environment variables will always be preset in the container, you can only use `-e` option to overwrite them:      
```
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TMPDIR=/tmp
SHELL=sh
container=ruri
```

*********************************************
```
-m, --mount [dir/dev/img/file] [target] .....: Mount dir/block-device/image/file to target
-M, --ro-mount [dir/dev/img/file] [target] ..: Mount dir/block-device/image/file as read-only
```
ruri provides a powerful mount function, here are some examples:
```
ruri -m /dev/sda1 / ./test
```
This command will mount /dev/sda1 to ./test and run container.      
```
ruri -m ./test.img / ./test
```
This command will mount ./test.img to ./test and run container.       
```
ruri -m /sdcard /sdcard ./test
```
This command will mount /sdcard to ./test/sdcard and run container.       
It can also bind-mount file/FIFO/socket.      
Note: For full spec of mount options, please refer [mount.md](mount.md).      
******************************************
```
-S, --host-runtime ..........................: Bind-mount /dev/, /sys/ and /proc/ from host
```
ruri will create /dev/, /sys/ and /proc/ after chroot(2) into container for better security. You can use `-S` option to force it to bind-mount system runtime dirs.    
Behavior note: This option might make info in /proc not accurate, might leak some info from host, and might cause some security issues. Enable it only if you know what you are doing.      
For more info, refer man page of mount(2), proc(5) and sysfs(5).      
*************************************
```
-R, --read-only .............................: Mount / as read-only
```
This will make the whole container rootfs read-only.      
***********************************************
```
-l, --limit [cpuset=cpu/memory=mem] .........: Set cpuset/memory limit
```
ruri currently supports cpuset and memory cgroup.            
Each `-l` option can only set one of the cpuset/memory limits      
for example:       
```
ruri -l memory=1M -l cpuset=1 /test
```
Note: This option need kernel support for specified cgroup.      
Note: This option is experimental, and may not work as expected. Report issues if you find any bugs.      
TODO: Add support for other cgroup limits like cpu, blkio, etc.      
For more info, refer man page of cgroups(7) and cgroup(7).      
**************************************************
```
-w, --no-warnings ...........................: Disable warnings
```
There might be some warnings when running ruri, if you don't like, use `-w` option to disable them.       
Note: This is just a cosmetic option, it will not affect the behavior of ruri.    
****************************************************
```
-f, --fork ..................................: fork() before exec the command
```
unshare and rootless container will always fork() before running commands in container,      
you can use this option to make common chroot container have the same behaiver.      
Note: This is only a useless option, I forgot why I added it, but it is here only for compatibility.      
******************************************************       
```
-j, --just-chroot ...........................: Just chroot, do not create the runtime dirs
```
If you enable this option, ruri will not create runtime dirs(/dev, proc and /sys) in container.       
And it will not setup cgroup limit.      
****************************************************
```
-W, --work-dir [dir]..........................: Change work directory in container.
```
default work directory is `/`, you can use this option to change it to other dirs.       
Note: this option is to compatible with other container implementations, it's useful when you run a docker container image with ruri.      
*********************************
```
-A, --unmask-dirs ............................: Unmask dirs in /proc and /sys
```
ruri will protect some files/dirs in /proc and /sys by default, use -A to disable this.      
Note: This option will downgrade the security of container, so use it with caution.      
********************
```
-E, --user [user/uid].........................: Set the user to run command in the container.
```
You can use this option to switch to a common user before exec(3).       
Behavior note: This option will parse user info from /etc/passwd in container, so you need to make sure the user exists in container. And, make sure that your container is secure that the user cannot modify the /etc/passwd file.      
*************
```
-t, --hostname [hostname] ....................: Set hostname
```
Set hostname, only for unshare container.      
Note: For non-unshare container, setting hostname in container will also affect the host, ruri does not support that, and it's not recommended to do so in container.      
************
```
-x, --no-network .............................: Disable network
```
Disable network, this option need net ns support and will enable unshare at the same time.      
Note: This option need kernel support for network namespaces.      
***********
```
-K, --use-kvm ...............................: Enable /dev/kvm support
```
Enable /dev/kvm for container.      
Note: This option need kernel and host support for KVM.      
Behavior note: This option will automatically add /dev/kvm to the container, so you can run KVM-based applications in the container.      
********
```
-I, --char-dev [device] [major] [minor] .....: Add a character device to container
```
Add a character device to container, for example `-I kvm 10 232` or `-I dri/card0 226 0`.      
Note: For security reason, creating block device is not supported, you can use `-m` option to mount a block device into container instead.      
Behavior note: This option will create a character device in /dev/ directory of the container, no need to add prefix `/dev/`.      
**********
```
-i, --hidepid 1/2 ...........................: Hidepid for /proc
```
Hidepid option for /proc.      
For more info, refer man page of proc(5).      
*********
```
-b, --background ............................: Fork to background
-L, --logfile [file] ........................: Set log file of -b option
```
Run ruri in background and set output file.      
Behavior note: This option will fork ruri to background and redirect output to the specified file. If no file is specified, it will use /dev/null as default.    
Note: ruri will print the PID of the background process to stdout, so you can use it to manage the background process later.      
*********
```
-X, --deny-syscall [syscall] ................: Deny a syscall
```
Use Seccomp to set SCMP_ACT_KILL for the syscall.      
Behavior note: This option will set the syscall to SCMP_ACT_KILL. And it will not affect the built-in seccomp profile.      
This option is isolated from the built-in seccomp profile, so using this option will not enable the built-in seccomp profile automatically.      
Note: This option is experimental, and may not work as expected. Report issues if you find any bugs.      
For more info, refer man page of seccomp(2), prctl(2) and seccomp(3).
*********
```
-O, --oom-score-adj [score] .................: Set oom_score_adj for container.
```
Set oom_score_adj, note that using negative value is dangerous. And, for negative value, it will not work with rootless container.     
For more info, refer man page of proc_pid_oom_score_adj(5).  