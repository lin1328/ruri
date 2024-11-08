#!/bin/bash
source global.sh

export TEST_NO=0
export DESCRIPTION="This script is used to create files and directories for testing."
show_test_description

export SUBTEST_NO=1
export SUBTEST_DESCRIPTION="Build ruri"
export TMPDIR=tmpdir-$RANDOM
show_subtest_description
cd ..
mkdir ${TMPDIR}
check_return_value $?
export TMPDIR=$(realpath ${TMPDIR})
./configure -d
check_return_value $?
make
check_return_value $?
mv ruri ${TMPDIR}
check_return_value $?
pass_subtest

export SUBTEST_NO=2
export SUBTEST_DESCRIPTION="Check ruri"
show_subtest_description
cd ${TMPDIR}
./ruri -v
check_return_value $?
pass_subtest

export SUBTEST_NO=3
export SUBTEST_DESCRIPTION="Get rootfs.tar.xz"
show_subtest_description
git clone https://github.com/moe-hacker/rootfstool
check_return_value $?
rootfstool/rootfstool d -d alpine -v edge
check_return_value $?
rm -rf rootfstool
check_return_value $?
pass_subtest

export SUBTEST_NO=4
export SUBTEST_DESCRIPTION="Create test.img"
show_subtest_description
if [[ -e /tmp/test ]]; then
  rm /tmp/test
fi
if [[ -d /tmp/test ]]; then
  ./ruri -U /tmp/test
  rm -rf /tmp/test
fi
dd if=/dev/zero of=test.img bs=1M count=256
check_return_value $?
mkfs.ext4 test.img
check_return_value $?
mkdir /tmp/test
check_return_value $?
LOOPFILE=$(losetup -f)
losetup ${LOOPFILE} ./test.img
mount ${LOOPFILE} /tmp/test
check_return_value $?
tar -xf rootfs.tar.xz -C /tmp/test
check_return_value $?
umount -lvf /tmp/test
check_return_value $?
pass_subtest

export SUBTEST_NO=5
export SUBTEST_DESCRIPTION="Create test2.img"
show_subtest_description
dd if=/dev/zero of=test2.img bs=1M count=256
check_return_value $?
mkfs.ext4 test2.img
check_return_value $?
LOOPFILE=$(losetup -f)
losetup ${LOOPFILE} ./test2.img
mount ${LOOPFILE} /tmp/test
check_return_value $?
touch /tmp/test/test.txt
check_return_value $?
echo "xxxxxxxxxxxx" >/tmp/test/test.txt
check_return_value $?
umount -lvf /tmp/test
check_return_value $?
pass_subtest

export SUBTEST_NO=6
export SUBTEST_DESCRIPTION="Create ./test as rootfs"
show_subtest_description
mkdir test
check_return_value $?
tar -xf rootfs.tar.xz -C test
check_return_value $?
pass_subtest
pass_test