#!/bin/bash

# Execution script for HOOKED_SYSCALL test
# This script only triggers the hooked uname syscall
# Module management is handled in the setup phase

# Simply call uname to trigger the hooked syscall
uname -a > /dev/null

# Give a moment for the event to be processed
sleep 1
