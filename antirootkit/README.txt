Antirootkit - kernel module to detect and cure FreeBSD kernel rootkits

WARNING! This software is VERY UNSTABLE and may cause KERNEL PANIC and DATA LOSS!
PLEASE GET SURE YOU DON'T HAVE ANY IMPORTANT DATA ON YOUR PC BEFORE RUNNING IT!

Usage:
1. Build kernel module - make install
2. Load kernel module - kldload antirootkit.ko
3. Use system call 211 to call antirootkit

System call has 1 integer parameter, which is a combination of flags:
OP_RESTORE_SYSCALLS     = 0x01 - Restore systems calls table
OP_RESTORE_KERN_FUNCS   = 0x02
 - Unhook system calls with found code injection
OP_UNHIDE_CONNECTIONS   = 0x04
 - Find hidden connections and restore them in connections list
OP_KILL_HIDDEN_PROCS    = 0x08 - Kill any hidden processes

Example: 
perl -e "syscall(211, 15)"