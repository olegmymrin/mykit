#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/syscall.h>
#include <sys/sx.h>
#include <sys/unistd.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/in_pcb.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/conf.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/linker.h>
#include <security/audit/audit.h>
#include <sys/limits.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <sys/cdefs.h>

#define OP_RESTORE_SYSCALLS     0x01
#define OP_RESTORE_KERN_FUNCS   0x02
#define OP_UNHIDE_CONNECTIONS   0x04
#define OP_KILL_HIDDEN_PROCS    0x08
