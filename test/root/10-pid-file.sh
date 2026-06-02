cd ${TEST_ROOT}
source global.sh

export TEST_NO=10
export DESCRIPTION="Test if pid file works properly"
show_test_description

export SUBTEST_NO=1
export SUBTEST_DESCRIPTION="RURI_EXITED_0"
show_subtest_description
cd ${TMPDIR}
./test_pid_file RURI_EXITED_0 ./test true
check_if_succeed $?
./ruri -U ./test
pass_subtest

export SUBTEST_NO=2
export SUBTEST_DESCRIPTION="RURI_EXITED_1"
show_subtest_description
cd ${TMPDIR}
./test_pid_file RURI_EXITED_1 ./test false
check_if_succeed $?
./ruri -U ./test

pass_subtest

pass_test
