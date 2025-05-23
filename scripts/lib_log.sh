#!/bin/sh

#
# log
#

__LIB_LOG_NAME="lib_log.sh"

# prevent multiple sourcing
if [ -n "${__LIB_LOG_SH_SOURCED}" ]; then
    return 0
fi
__LIB_LOG_SH_SOURCED=1

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_LOG_NAME}")
        printf "[%s]: %s\n" "${__LIB_LOG_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

# shellcheck disable=SC1091
. "${0%/*}/lib_internal.sh" || {
    status=$?
    printf "[%s]: %s\n" "${__LIB_LOG_NAME}" "Failed to source lib_internal.sh"
    return ${status}
}

############
# functions
############

# log logs a script message with timestamp and level.
#
# $1: LEVEL - Log level (e.g., INFO, WARN, ERROR).
# $2: MESSAGE - Message to log.
#
# Usage:
#   log LEVEL MESSAGE...
#
# Example:
#   log "INFO" "This is an informational message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [INFO] This is an informational message.
log() {
    log_level="$1"
    if [ -z "${log_level}" ]; then
        __error "log: No LEVEL provided"
        return 1
    fi
    shift

    printf '[%s] [%s] [%s] %s\n' "$(__get_timestamp)" "${__SCRIPT_NAME}" "${log_level}" "$*" >&2
}

# debug logs a debug-level message if DEBUG is set.
#
# $1: MESSAGE - Debug message to log.
#
# Usage:
#   debug MESSAGE...
#
# Example:
#   debug "This is a debug message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [DEBUG] This is a debug message.
debug() {
    if [ "${DEBUG}" -eq 0 ]; then
        return 0
    fi

    log "DEBUG" "$@" || {
        status=$?
        __error "debug: Failed to log message"
        return ${status}
    }
}

# info logs an informational message.
#
# $1: MESSAGE - Informational message to log.
#
# Usage:
#   info MESSAGE...
#
# Example:
#   info "This is an informational message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [INFO] This is an informational message.
info() {
    log "INFO" "$@" || {
        status=$?
        __error "info: Failed to log message"
        return ${status}
    }
}

# warn logs a warning message.
#
# $1: MESSAGE - Warning message to log.
#
# Usage:
#  warn MESSAGE...
#
# Example:
#   warn "This is a warning message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [WARN] This is a warning message.
warn() {
    log "WARN" "$@" || {
        status=$?
        __error "warn: Failed to log message"
        return ${status}
    }
}

# error logs an error message.
#
# $1: MESSAGE - Error message to log.
#
# Usage:
#  error MESSAGE...
#
# Example:
#   error "This is an error message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [ERROR] This is an error message.
error() {
    log "ERROR" "$@" || {
        status=$?
        __error "error: Failed to log message"
        return ${status}
    }
}
