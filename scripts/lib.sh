#!/bin/sh

#
# lib.sh internal
#

__LIB_NAME="lib.sh"

# must be sourced, not executed
(return 0 2>/dev/null) || {
    printf '[%s]: This script must be sourced, not executed.\n' "$__LIB_NAME" >&2
    exit 1
}

# prevent multiple sourcing
[ -n "$__LIB_SH_INCLUDED" ] && return 0
__LIB_SH_INCLUDED=1

# set default DEBUG level
if [ -n "$DEBUG" ]; then
    case "$DEBUG" in
    '' | *[!0-9]*)
        DEBUG=0
        ;;
    *)
        DEBUG="${DEBUG#0}"
        ;;
    esac
else
    DEBUG=0
fi

# enable shell tracing if DEBUG is greater than 1
if [ "$DEBUG" -gt 1 ]; then
    set -x
fi

__SCRIPT_NAME="${0##*/}" # POSIX-safe script name (no 'basename' dependency)

# Check date availability once for performance (0 = false, 1 = true)
if command -v date >/dev/null 2>&1; then
    __CMD_DATE_AVAILABLE=1
else
    __CMD_DATE_AVAILABLE=0
fi

# __log logs an internal library message with timestamp and level.
# Usage (internal):
#   __log LEVEL MESSAGE...
# Example:
#   __log "INFO" "This is an informational message."
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [lib.sh] [INFO] This is an informational message.
__log() {
    level="$1"
    shift

    if [ "$__CMD_DATE_AVAILABLE" -eq 1 ]; then
        timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    else
        timestamp="1970-01-01T00:00:00Z"
    fi

    printf '[%s] [%s] [%s] [%s] %s\n' "$timestamp" "$__SCRIPT_NAME" "$__LIB_NAME" "$level" "$*" >&2
}

# __collect_missing_cmds collects missing commands from a given list.
# Usage (internal):
#   __collect_missing_cmds CMD1 CMD2...
# Example:
#   __collect_missing_cmds git grep sed
# Output:
#   git grep sed # if any are missing
#   # (empty if all commands are available)
__collect_missing_cmds() {
    missing=""

    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing="$missing $cmd"
        fi
    done

    printf "%s" "$missing"
}

# __lib_require_cmds checks for required commands and exits if any are missing (error code 127).
# Usage (internal):
#   __lib_require_cmds CMD1 CMD2...
# Example:
#   __lib_require_cmds git grep sed
__lib_require_cmds() {
    missing="$(__collect_missing_cmds "$@")"

    if [ -n "$missing" ]; then
        __log "ERROR" "The following required command(s) are missing:$missing"
        __log "ERROR" "Please install the missing dependencies and try again."
        exit 127
    fi
}

# assuming as available built-ins: printf, test, command, shift, set, exit
__lib_require_cmds date tr

#
# logging functions
#

# log logs a script message with timestamp and level.
# Usage:
#   log LEVEL MESSAGE...
# Example:
#   log "INFO" "This is an informational message."
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [INFO] This is an informational message.
log() {
    level="$1"
    shift

    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '[%s] [%s] [%s] %s\n' "$timestamp" "$__SCRIPT_NAME" "$level" "$*" >&2
}

# debug logs a debug-level message if DEBUG is set.
# Usage:
#   debug MESSAGE...
# Example:
#   debug "This is a debug message."
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [DEBUG] This is a debug message.
debug() {
    [ "$DEBUG" -gt 0 ] && log "DEBUG" "$@"
}

# info logs an informational message.
# Usage:
#   info MESSAGE...
# Example:
#   info "This is an informational message."
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [INFO] This is an informational message.
info() {
    log "INFO" "$@"
}

# warn logs a warning message.
# Usage:
#  warn MESSAGE...
# Example:
#   warn "This is a warning message."
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [WARN] This is a warning message.
warn() {
    log "WARN" "$@"
}

# error logs an error message.
# Usage:
#  error MESSAGE...
# Example:
#   error "This is an error message."
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [ERROR] This is an error message.
error() {
    log "ERROR" "$@"
}

#
# exit functions
#

# die logs an error message and exits with a given code (default: 1).
# Usage:
#   die MESSAGE [CODE]
# Example:
#   die "This is a fatal error." 127
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [ERROR] This is a fatal error.
#   Exits with code 127.
die() {
    msg="$1"
    code="${2:-1}"

    error "$msg"
    exit "$code"
}

#
# print functions
#

__BLOCK_SEP_CHAR="-"
__BLOCK_SEP_SPACE=" "
__BLOCK_SEP_LINE=""

# print_script_start logs the start of a script with a decorative title.
# Usage:
#   print_script_start TITLE
# Example:
#   print_script_start "My Script Title"
# Output:
#   --- My Script Title ---
print_script_start() {
    title="$1"
    log "INFO" "${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_SPACE}$title${__BLOCK_SEP_SPACE}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}"

    sep_len=$((3 + 1 + ${#title} + 1 + 3))
    __BLOCK_SEP_LINE=$(printf "%${sep_len}s" | tr ' ' "$__BLOCK_SEP_CHAR")

    # print at the end of the script
    trap __print_script_end EXIT
}

# __print_script_end logs a decorative separator at the end of the script.
# Usage (internal):
#  __print_script_end
__print_script_end() {
    log "INFO" "$__BLOCK_SEP_LINE"
}

# set_print_block_sep sets the character used for decorative separators.
# Usage:
#   set_print_block_sep CHARACTER
# Example:
#   set_print_block_sep "#"
set_print_block_sep() {
    if [ -n "$1" ] && [ "${#1}" -eq 1 ]; then
        __BLOCK_SEP_CHAR="$1"
    else
        warn "Block separator must be a single character. Ignoring '$1' and using '$__BLOCK_SEP_CHAR'."
    fi
}

#
# git
#

# git_changed_files lists filenames changed between two refs matching the given pattern.
# $1: REF1 - Base git reference for comparison.
# $2: REF2 - Target git reference for comparison.
# $3: PATTERN - File pattern to filter git diff results.
# Usage:
#   git_changed_files REF1 REF2 PATTERN
# Example:
#   git_changed_files HEAD~2 HEAD 'path/*.md'
# Output:
#   path/file1.md
#   path/file2.md
git_changed_files() {
    git diff --name-only "$1..$2" -- "$3" | xargs -n1
}

#
# misc functions
#

# require_cmds checks for required commands and exits if any are missing (error code 127).
# Usage:
#   require_cmds CMD1 CMD2...
# Example:
#   require_cmds git grep sed
require_cmds() {
    missing="$(__collect_missing_cmds "$@")"

    if [ -n "$missing" ]; then
        error "The following required command(s) are missing:$missing"
        die "Please install the missing dependencies and try again." 127
    fi
}

# basename_strip_ext extracts basenames from filenames by removing the given extension.
# $1: FILES - List of filenames.
# $2: EXTENSION - File extension to remove.
# Usage:
#   basename_strip_ext FILES EXTENSION
# Example:
#   basename_strip_ext "path/file1.txt path/file2.txt" ".txt"
# Output:
#   file1
#   file2
basename_strip_ext() {
    files="$1"
    ext="$2"
    ext="${ext#.}" # remove leading dot if present

    if [ -n "$files" ]; then
        printf "%s\n" "$files" | xargs -n1 basename | sed "s/\.$ext\$//"
    else
        printf "" # return empty string
    fi
}

# sanitize_to_lines converts a string to a list of lines, removing leading/trailing whitespace.
# $1: INPUT - Input string to sanitize.
# $2: DELIMITER - Delimiter to split the input string (default: space).
# Usage:
#   sanitize_to_lines INPUT [DELIMITER]
# Example1:
#   sanitize_to_lines "apple banana cherry date"
#   sanitize_to_lines "apple,banana, cherry , date" ","
#   sanitize_to_lines "apple\nbanana\ncherry\ndate"
# Output1:
#   apple
#   banana
#   cherry
#   date
sanitize_to_lines() {
    input=$1
    delimiter=$2

    if [ -z "$delimiter" ]; then
        delimiter=" "
    fi

    # Interpret \n sequences as real newlines, split with delimiter, remove empties & trim
    printf "%b" "$input" |
        tr "$delimiter" '\n' |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
        sed '/^$/d'
}

# list_diff prints symmetric difference between two lists.
# It outputs only items that are unique to each list.
# Usage:
#   list_diff "$list_a" "$list_b"
# Example:
#   list_diff "a\nb\nc" "b\nc\nd"
#   list_diff "a b c" "b c d"
# Output:
#   a
#   d
list_diff() {
    list_a=$(sanitize_to_lines "$1" | sort -u)
    list_b=$(sanitize_to_lines "$2" | sort -u)

    # items in a not in b
    printf "%s\n" "$list_a" | while IFS= read -r item; do
        printf "%s" "$list_b" | grep -Fxq "$item" || printf "%s\n" "$item"
    done

    # items in b not in a
    printf "%s\n" "$list_b" | while IFS= read -r item; do
        printf "%s" "$list_a" | grep -Fxq "$item" || printf "%s\n" "$item"
    done
}

#
# test functions
#

__TEST_ALL_PASSED=0
__TEST_FAILED_TESTS=""
__TEST_FAILED_ASSERTS=""

test_init() {
    __TEST_ALL_PASSED=0
    __TEST_FAILED_TESTS=""
    __TEST_FAILED_ASSERTS=""
}

test_pass() {
    msg="$1"
    code="$2"

    [ -z "$code" ] && code=0
    printf "[PASS] %s (exit: %d)\n" "$msg" "$code"
}

test_fail() {
    msg="$1"
    code="$2"

    [ -z "$code" ] && code=1
    printf "[FAIL] %s (exit: %d)\n" "$msg" "$code"

    if [ -n "$current_test_fn" ]; then
        __TEST_FAILED_ASSERTS=$(printf "%s\n - %s: %s" "$__TEST_FAILED_ASSERTS" "$current_test_fn" "$msg")
    else
        __TEST_FAILED_ASSERTS=$(printf "%s\n - %s" "$__TEST_FAILED_ASSERTS" "$msg")
    fi

    return 1
}

test_assert_eq() {
    expected="$1"
    actual="$2"
    desc="$3"
    code="${4:-0}"

    [ "$expected" = "$actual" ] && test_pass "$desc" "$code" || {
        printf "Expected: '%s', Got: '%s'\n" "$expected" "$actual"
        test_fail "$desc" "$code"
    }
}

test_assert_neq() {
    not_expected="$1"
    actual="$2"
    desc="$3"
    code="${4:-0}"

    [ "$not_expected" != "$actual" ] && test_pass "$desc" "$code" || {
        printf "Did not expect: '%s', but got: '%s'\n" "$not_expected" "$actual"
        test_fail "$desc" "$code"
    }
}

test_run() {
    name="$1"
    shift
    current_test_fn="$1"

    prev_failed_asserts="$__TEST_FAILED_ASSERTS"

    printf "== %s: Running ==\n" "$name"
    "$@"
    result=$?

    if [ "$result" -ne 0 ] || [ "$__TEST_FAILED_ASSERTS" != "$prev_failed_asserts" ]; then
        __TEST_ALL_PASSED=1
        __TEST_FAILED_TESTS=$(printf "%s\n - %s (%s)\n" "$__TEST_FAILED_TESTS" "$name" "$current_test_fn")
    fi

    printf "== %s: Completed ==\n\n" "$name"
    current_test_fn=""
}

# test_summary prints a summary of test results and exits appropriately.
test_summary() {
    if [ "$__TEST_ALL_PASSED" -eq 0 ]; then
        test_pass "All tests completed successfully" 0
    else
        printf "Failed tests:\n%s\n" "$__TEST_FAILED_TESTS"
        printf "\nFailed assertions:\n%s\n\n" "$__TEST_FAILED_ASSERTS"
        test_fail "Some tests failed" 1
    fi
}

#
# lib overview
#

debug "Debug mode is enabled"
debug "$__LIB_NAME successfully loaded"
debug "Script name: $0"
debug "Script PID: $$"
debug "Script arguments: $*"
