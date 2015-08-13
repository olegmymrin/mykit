#include "antirootkit.h"

unsigned long CR0REG;

#define read_cr0(x)  __asm__("mov %%cr0,%0\n\t" :"=r"(x):)
  
#define write_cr0(x) __asm__("mov %0,%%cr0\n\t" ::"r"(x))


int overwrite_syscalls = 1;
int overwrite_kernel_functions = 0;
int unhide_conns = 0;
int kill_procs = 0;

unsigned kern_max_offset;
unsigned kern_start;

extern linker_file_list_t linker_files;
extern struct sx kld_sx;

#define MAX_MESSAGE_NUMBER 500

struct hook_messages{
  char* messages[MAX_MESSAGE_NUMBER];
  size_t len;
  struct sx hook_messages_lock;
} hook_messages;

struct checkcall_args;

static void enter_mi_switch(int flags, struct thread *newtd);
static void hook_mi_switch(int flags, struct thread *newtd);
static void allow_write(void);
static void disallow_write(void);

static void check_syscalls(void);
static void print_antirootkit_messages(void);
static void check_kernel_funcs(struct thread*);
static void check_conns(void);

static int checkcall(struct thread *td, struct checkcall_args *uap);;

static int my_sys_read(struct thread *td, struct read_args *uap)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (uap->nbyte > INT_MAX)
		return (EINVAL);
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = uap->nbyte;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_readv(td, uap->fd, &auio);
	return(error);
}

static void enter_mi_switch(int flags, struct thread *newtd)
{
    __asm__ volatile( 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
    "nop\n\t" 
  );
}

int last_hidden_pid = -1;
struct proc *last_proc = NULL;



#define CHECK_SYSCALL(x) { \
  if (sysent[SYS_##x].sy_call != (sy_call_t *)x) \
  { \
    sx_xlock(&hook_messages.hook_messages_lock);\
    hook_messages.messages[hook_messages.len] = malloc(strlen("syscall " #x) + 1, M_DEVBUF, M_NOWAIT); \
    memcpy(hook_messages.messages[hook_messages.len++], "syscall " #x, strlen("syscall " #x) + 1);\
    sx_xunlock(&hook_messages.hook_messages_lock);\
    if (overwrite_syscalls) \
	sysent[SYS_##x].sy_call = (sy_call_t*)x; \
  } \
}


#define SET_FUNCTION_HOOK(x, hook_x, first_instructions_len) { \
  char *call_ret_code = (unsigned char *)malloc(5, M_DEVBUF, M_NOWAIT); \
  memcpy(call_ret_code, "\xe9\x00\x00\x00\x00",5); \
  int offset = ((char*)hook_x - (char*)x) - 5; \
  memcpy((char*)(call_ret_code + 1), &offset, 4); \
  critical_enter(); \
  allow_write(); \
  memcpy((char*)enter_##x, (char*)x, first_instructions_len); \
  memcpy((char*)x, call_ret_code, 5); \
  disallow_write(); \
  critical_exit(); \
  offset = ((char*)x - (char*)enter_##x) - 5;  \
  memcpy((char*)(call_ret_code + 1), &offset, 4); \
  critical_enter(); \
  allow_write(); \
  memcpy((char*)enter_##x + first_instructions_len, call_ret_code, 5); \
  disallow_write(); \
  critical_exit(); \
  free(call_ret_code, M_DEVBUF); \
} 

#define UNSET_FUNCTION_HOOK(x, first_instructions_len) { \
  critical_enter(); \
  allow_write(); \
  memcpy((char*)x, (char*)enter_##x, first_instructions_len); \
  disallow_write(); \
  critical_exit(); \
}


//-----------------------------------------------

#define CHECK_KERN_FUNC(td, x) {\
  if (memcmp((char*)x, "\xe9", 1) == 0 || memcmp((char*)x, "\xe8", 1) == 0) \
  { \
    int offset;\
    memcpy(&offset,(char*)x + 1,4); \
    if ((unsigned)((char*)x + offset) > kern_max_offset) \
    {\
      sx_xlock(&hook_messages.hook_messages_lock);\
      hook_messages.messages[hook_messages.len] = malloc(strlen("function " #x) + 1, M_DEVBUF, M_NOWAIT); \
      memcpy(hook_messages.messages[hook_messages.len++], "function " #x, strlen("function " #x) + 1);\
      sx_xunlock(&hook_messages.hook_messages_lock);\
      if (overwrite_kernel_functions)\
      {\
	int error;\
	int fd;\
	error = kern_open(td, "/boot/kernel/kernel", UIO_SYSSPACE, O_RDONLY, 0);\
	fd = td->td_retval[0];\
	if (error)\
	{\
	  uprintf("antirootkit: cannot open kernel\n");\
	  return;\
	}\
	struct lseek_args alseek_args;\
	alseek_args.fd = fd;\
	alseek_args.offset = (unsigned)x - kern_start;\
	alseek_args.whence = SEEK_SET;\
	error = lseek(td, &alseek_args);\
	if (error)\
	{\
	  uprintf("antirootkit: cannot seek kernel %d\n", error);\
	  return;\
	}\
	struct read_args aread_args;\
	aread_args.fd = fd;\
	aread_args.nbyte = 6;\
	aread_args.buf = malloc(6, M_DEVBUF, M_NOWAIT);   \
	error = my_sys_read(td, &aread_args);\
	if (error || td->td_retval[0] != 6)\
	{\
	  uprintf("antirootkit: cannot read kernel\n");\
	  return;\
	}      \
	critical_enter(); \
	allow_write(); \
	memcpy((char*)x, aread_args.buf, 6); \
	disallow_write(); \
	critical_exit(); \
	close(td, (struct close_args*)&fd);\
	free(aread_args.buf, M_DEVBUF);\
      }\
    }\
  } \
}

static void 
allow_write()
{
  read_cr0(CR0REG);
  CR0REG &= 0xfffeffff;
  write_cr0(CR0REG);
}

static void 
disallow_write()
{
  read_cr0(CR0REG);
  CR0REG |= 0x10000;
  write_cr0(CR0REG);
}


static void 
check_syscalls()
{
    CHECK_SYSCALL(open);
    CHECK_SYSCALL(openat);
    CHECK_SYSCALL(getdirentries);
    CHECK_SYSCALL(stat);
    CHECK_SYSCALL(lstat);
    CHECK_SYSCALL(chdir);
    CHECK_SYSCALL(listen);
    CHECK_SYSCALL(accept);
    CHECK_SYSCALL(link);
    CHECK_SYSCALL(unlink);
    CHECK_SYSCALL(dup);
    CHECK_SYSCALL(dup2);
    CHECK_SYSCALL(fork);
    CHECK_SYSCALL(vfork);
    CHECK_SYSCALL(rfork);
}


static void 
check_kernel_funcs(struct thread *td)
{
    CHECK_KERN_FUNC(td, open);
    CHECK_KERN_FUNC(td, openat);
    CHECK_KERN_FUNC(td, getdirentries);
    CHECK_KERN_FUNC(td, stat);
    CHECK_KERN_FUNC(td, lstat);
    CHECK_KERN_FUNC(td, chdir);
    CHECK_KERN_FUNC(td, listen);
    CHECK_KERN_FUNC(td, accept);
    CHECK_KERN_FUNC(td, link);
    CHECK_KERN_FUNC(td, unlink);
    CHECK_KERN_FUNC(td, dup);
    CHECK_KERN_FUNC(td, dup2);
    CHECK_KERN_FUNC(td, fork);
    CHECK_KERN_FUNC(td, vfork);
    CHECK_KERN_FUNC(td, rfork);
}

//-----------------------------------------------

static void  
print_antirootkit_messages()
{
    int i;

    sx_xlock(&hook_messages.hook_messages_lock);
    if ( hook_messages.len > 0 )
      uprintf("Found hooks:\n");
    else
      uprintf("Hooks not found\n");
    for (i = 0; i < hook_messages.len; ++i)
    {
        uprintf("%s\n", hook_messages.messages[i]);
	free(hook_messages.messages[i], M_DEVBUF);
    }
    hook_messages.len = 0;
    sx_xunlock(&hook_messages.hook_messages_lock);
}
//-------------------------------------

static void 
check_conns()
{
    struct inpcbhead
    *head;
    struct inpcb *inp1, *inp2, *inp3;
    int found;

    INP_INFO_RLOCK(&tcbinfo);
    LIST_FOREACH(inp1, tcbinfo.ipi_listhead, inp_list) 
    {
      INP_WLOCK(inp1);
      head = &tcbinfo.ipi_hashbase[INP_PCBHASH(inp1->inp_inc.inc_laddr.s_addr, inp1->inp_inc.inc_lport, inp1->inp_inc.inc_fport, tcbinfo.ipi_hashmask)];
      LIST_FOREACH(inp2, head, inp_hash) 
      {
	  INP_WLOCK(inp2);
	  found = 0;
      
	  LIST_FOREACH(inp3, tcbinfo.ipi_listhead, inp_list) 
	  {
	      INP_WLOCK(inp3);
	      if (inp2 == inp3) 
	      {
		  found = 1;
		  INP_WUNLOCK(inp3);
		  break;
	      }   
	      INP_WUNLOCK(inp3);
	  }
	  
	  if (!found)
	  {
	    char *conname = malloc(256, M_DEVBUF, M_NOWAIT);
	    sprintf(conname, "connection lport = %d fport = %d\n", inp2->inp_inc.inc_lport, inp2->inp_inc.inc_fport);
	    hook_messages.messages[hook_messages.len++] = conname;
	    if (unhide_conns)
	    {
	      LIST_INSERT_HEAD(tcbinfo.ipi_listhead, inp2, inp_list);
	      tcbinfo.ipi_count++;
	    }
	  }
	  INP_WUNLOCK(inp2);
      }
      INP_WUNLOCK(inp1);
    }
    INP_INFO_RUNLOCK(&tcbinfo);
}
//-------------------------------------

static void 
hook_mi_switch(int flags, struct thread *newtd)
{
    struct proc *pproc;
    int find = 0;
    LIST_FOREACH(pproc, &allproc, p_list)
    {
	if (curthread->td_proc->p_pid == pproc->p_pid)
	{
	  find = 1;
	  break;
	}
    }
    if (!find)
    {
	last_hidden_pid = curthread->td_proc->p_pid;
	last_proc = curthread->td_proc;
    }
    
    enter_mi_switch(flags, newtd);
}

struct checkcall_args {
  int op;
};

static int
checkcall(struct thread *td, struct checkcall_args *uap)
{
  if (last_hidden_pid != -1)
    uprintf("Last hidden pid = %d\n", last_hidden_pid);
  else
    uprintf("No pids hidden\n");
  
  overwrite_syscalls = uap->op & OP_RESTORE_SYSCALLS;
  overwrite_kernel_functions = uap->op & OP_RESTORE_KERN_FUNCS;
  unhide_conns = uap->op & OP_UNHIDE_CONNECTIONS;
  kill_procs = uap->op & OP_KILL_HIDDEN_PROCS;
  
  if(kill_procs)
  {
      ksiginfo_t ksi;
      ksiginfo_init(&ksi);
      ksi.ksi_signo = SIGKILL;
      ksi.ksi_code = SI_USER;
      ksi.ksi_pid = td->td_proc->p_pid;
      ksi.ksi_uid = td->td_ucred->cr_ruid;
      PROC_LOCK(last_proc);
      int error = p_cansignal(td, last_proc, SIGKILL);
      if (error == 0)
	  pksignal(last_proc, SIGKILL, &ksi);
      PROC_UNLOCK(last_proc);
      last_proc = NULL;
      last_hidden_pid = -1;
  }

  check_syscalls();

  check_kernel_funcs(td);

  check_conns();

  print_antirootkit_messages();

  return 0;
}


struct sysent old_sysent;

struct sysent check_proc_sysent = {
    1,
    (sy_call_t *)checkcall
};

static int 
load(struct module *module, int cmd, void *arg)
{
  switch (cmd)
  {
    case MOD_LOAD:
    {
      hook_messages.len = 0;
      
      SET_FUNCTION_HOOK(mi_switch, hook_mi_switch, 5);
      
      sx_init(&hook_messages.hook_messages_lock, NULL);
      
      sx_xlock(&kld_sx);
      linker_file_t lf;
      TAILQ_FOREACH(lf, &linker_files, link)
      {
	if (strcmp(lf->filename, "kernel") == 0)
	  break;
      }
      kern_start = (unsigned)lf->address;
      kern_max_offset = (unsigned)lf->address + lf->size;
      sx_xunlock(&kld_sx);
      
      old_sysent = sysent[211];
      sysent[211] = check_proc_sysent;
      
      break;
    }
    case MOD_UNLOAD:
    {
      UNSET_FUNCTION_HOOK(mi_switch, 5);
      sysent[211] = old_sysent;
      break;
    }
  }
  
  return 0;
}

static moduledata_t antirootkit_mod = {
  "antirootkit",  /* module name */
  load,         /* event handler */
  NULL          /* extra data */
};

DECLARE_MODULE(antirootkit, antirootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
