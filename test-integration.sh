#!/bin/bash

set -ue
ABSOLUTE_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)
source $ABSOLUTE_PATH/lstore-functions.sh

function run_test_case() {
    # run_test_case <test function>
    TEST_FUNCTION=$1
    shift
    # This chicanery is to allow suppressing output going to the terminal unless
    # the test case fails. Additionally, the same bits can be used to store
    # the outputs for use w/writing a junit XML file (which can be parsed with
    # other tools).
    #
    # Unfortunately, the bash-ninjitsu to get redirections point the right way
    # is non-trivial. I'll get back to it soon, hopefully.
    $TEST_FUNCTION "$@" 3>&1 4>&2 &
    FUNCTION_PID=$!

    if wait $FUNCTION_PID; then
        echo "ok $TEST_FUNCTION"
    else
        echo "bad $TEST_FUNCTION"
        exit 1
    fi
}
function test_fail() {
    echo "Fail Stdout 1"
    >&2 echo "Fail Stderr 1"
    echo "Fail Stdout 2"
    >&2 echo "Fail Stderr 2"
    return 1
}
function test_win() {
    echo "Stdout 1"
    >&2 echo "Stderr 1"
    echo "Stdout 2"
    >&2 echo "Stderr 2"
    return 0
}

function start_gridftp() {
    set -ex
    globus-gridftp-server -debug -dsi lfs:/etc/lio/lio-gridftp.cfg -port 2812 \
        -log-level ALL -log-module stdio:buffer,interval=1 -logfile "" -L "" \
        -allow-anonymous -anonymous-user $(whoami)
}
function stop_gridftp() {
    local GRIDFTP_PID=$1
    kill $1

}

function test_read() {
    start_gridftp &
    GRIDFTP_PID=$!

    stop_gridftp $GRIDFTP_PID
}
run_test_case test_win
run_test_case test_read
