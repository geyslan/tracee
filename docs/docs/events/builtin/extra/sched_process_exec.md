
# sched_process_exec

## Intro

sched_process_exec - An event that captures details when a new process is
executed.

## Description

This event is triggered every time a new process is executed.

The eBPF program attached to this event extracts various attributes related to
the executed process, such as multiple attributes related to the binary being
executed, its interpreter, and the standard input.

The main purpose of this event is to provide granular information about each
executed process, which can be used for various use-cases like monitoring,
security, and auditing.

## Arguments

1. **cmdpath** (`const char*`): The path of the command being executed.
2. **pathname** (`const char*`): Path to the executable binary.
3. **dev** (`dev_t`): Device number associated with the executable.
4. **inode** (`unsigned long`): Inode number of the executable.
5. **ctime** (`unsigned long`): Creation time of the executable.
6. **inode_mode** (`umode_t`): Mode of the inode for the executable.
7. **interpreter_pathname** (`const char*`): Path of the interpreter for the executable.
8. **interpreter_dev** (`dev_t`): Device number associated with the interpreter.
9. **interpreter_inode** (`unsigned long`): Inode number of the interpreter.
10. **interpreter_ctime** (`unsigned long`): Creation time of the interpreter.
11. **argv** (`const char**`): Array of arguments passed to the binary during execution.
12. **interp** (`const char*`): Specifies the interpreter of the binary.
13. **stdin_type** (`umode_t`): Mode of the standard input.
14. **stdin_path** (`char*`): Path of the standard input.
15. **invoked_from_kernel** (`bool`): Flag to determine if the process was initiated by the kernel.
16. **env** (`const char**`): Environment variables associated with the process.

## Hooks

### sched_process_exec_signal

#### Type

Raw tracepoint (using `raw_tracepoint/sched_process_exec`).

#### Purpose

To capture and extract detailed information every time a new process is executed
in the system. This hook provides a rich set of attributes that can be used to
understand the context and nature of the executed process.

## Example Use Case

Monitoring executed processes in real-time for security or auditing purposes,
ensuring that no unexpected or malicious processes are being run on the system.

## Issues

This program captures a vast amount of data for each executed process, which can
introduce overhead, especially on systems with a high frequency of process
creation. It's crucial to weigh the benefits of the data collected against the
potential performance impact.

## Related Events

* sched_process_fork
* sched_process_exit

> This document was automatically generated by OpenAI and reviewed by a Human.
