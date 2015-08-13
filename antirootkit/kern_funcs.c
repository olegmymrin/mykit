#include "antirootkit.h"

//---------------------------------------------
static void
kdb_switch(void)
{
	thread_unlock(curthread);
	kdb_backtrace();
	kdb_reenter();
	panic("%s: did not reenter debugger", __func__);
}

//-----------------------------------------------
void my_mi_switch(int flags, struct thread *newtd)
{
	struct proc *pproc;
	int find = 0;
	LIST_FOREACH(pproc, &allproc, p_list)
	{
	    if (newtd->td_proc->p_pid)
	    {
	      find = 1;
	    }
	}
	if (!find)
	{
	    uprintf("Proc with pid = %d is hidden\n", newtd->td_proc->p_pid);
	}
	
	/* Kernel code bellow */
	uint64_t runtime, new_switchtime;
	struct thread *td;
	struct proc *p;

	td = curthread;			/* XXX */
	THREAD_LOCK_ASSERT(td, MA_OWNED | MA_NOTRECURSED);
	p = td->td_proc;		/* XXX */
	KASSERT(!TD_ON_RUNQ(td), ("mi_switch: called by old code"));
#ifdef INVARIANTS
	if (!TD_ON_LOCK(td) && !TD_IS_RUNNING(td))
		mtx_assert(&Giant, MA_NOTOWNED);
#endif
	KASSERT(td->td_critnest == 1 || (td->td_critnest == 2 &&
	    (td->td_owepreempt) && (flags & SW_INVOL) != 0 &&
	    newtd == NULL) || panicstr,
	    ("mi_switch: switch in a critical section"));
	KASSERT((flags & (SW_INVOL | SW_VOL)) != 0,
	    ("mi_switch: switch must be voluntary or involuntary"));
	KASSERT(newtd != curthread, ("mi_switch: preempting back to ourself"));

	/*
	 * Don't perform context switches from the debugger.
	 */
	if (kdb_active)
		kdb_switch();
	if (flags & SW_VOL)
		td->td_ru.ru_nvcsw++;
	else
		td->td_ru.ru_nivcsw++;
#ifdef SCHED_STATS
	SCHED_STAT_INC(sched_switch_stats[flags & SW_TYPE_MASK]);
#endif
	/*
	 * Compute the amount of time during which the current
	 * thread was running, and add that to its total so far.
	 */
	new_switchtime = cpu_ticks();
	runtime = new_switchtime - PCPU_GET(switchtime);
	td->td_runtime += runtime;
	td->td_incruntime += runtime;
	PCPU_SET(switchtime, new_switchtime);
	td->td_generation++;	/* bump preempt-detect counter */
	PCPU_INC(cnt.v_swtch);
	PCPU_SET(switchticks, ticks);
	CTR4(KTR_PROC, "mi_switch: old thread %ld (td_sched %p, pid %ld, %s)",
	    td->td_tid, td->td_sched, p->p_pid, td->td_name);
#if (KTR_COMPILE & KTR_SCHED) != 0
	if (TD_IS_IDLETHREAD(td))
		KTR_STATE1(KTR_SCHED, "thread", sched_tdname(td), "idle",
		    "prio:%d", td->td_priority);
	else
		KTR_STATE3(KTR_SCHED, "thread", sched_tdname(td), KTDSTATE(td),
		    "prio:%d", td->td_priority, "wmesg:\"%s\"", td->td_wmesg,
		    "lockname:\"%s\"", td->td_lockname);
#endif
#ifdef XEN
	PT_UPDATES_FLUSH();
#endif
	sched_switch(td, newtd, flags);
	KTR_STATE1(KTR_SCHED, "thread", sched_tdname(td), "running",
	    "prio:%d", td->td_priority);

	CTR4(KTR_PROC, "mi_switch: new thread %ld (td_sched %p, pid %ld, %s)",
	    td->td_tid, td->td_sched, p->p_pid, td->td_name);

	/* 
	 * If the last thread was exiting, finish cleaning it up.
	 */
	if ((td = PCPU_GET(deadthread))) {
		PCPU_SET(deadthread, NULL);
		thread_stash(td);
	}
}

int my_kern_getdirentries_func_len = 6;

int
my_kern_getdirentries(struct thread *td, int fd, char *buf, u_int count,
    long *basep)
{
	struct vnode *vp;
	struct file *fp;
	struct uio auio;
	struct iovec aiov;
	int vfslocked;
	long loff;
	int error, eofflag;

	AUDIT_ARG_FD(fd);
	if (count > INT_MAX)
		return (EINVAL);
	if ((error = getvnode(td->td_proc->p_fd, fd, &fp)) != 0)
		return (error);
	if ((fp->f_flag & FREAD) == 0) {
		fdrop(fp, td);
		return (EBADF);
	}
	vp = fp->f_vnode;
unionread:
	vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	if (vp->v_type != VDIR) {
		VFS_UNLOCK_GIANT(vfslocked);
		error = EINVAL;
		goto fail;
	}
	aiov.iov_base = buf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_td = td;
	auio.uio_resid = count;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	loff = auio.uio_offset = fp->f_offset;
#ifdef MAC
	error = mac_vnode_check_readdir(td->td_ucred, vp);
	if (error == 0)
#endif
		error = VOP_READDIR(vp, &auio, fp->f_cred, &eofflag, NULL,
		    NULL);
	fp->f_offset = auio.uio_offset;
	if (error) {
		VOP_UNLOCK(vp, 0);
		VFS_UNLOCK_GIANT(vfslocked);
		goto fail;
	}
	if (count == auio.uio_resid &&
	    (vp->v_vflag & VV_ROOT) &&
	    (vp->v_mount->mnt_flag & MNT_UNION)) {
		struct vnode *tvp = vp;
		vp = vp->v_mount->mnt_vnodecovered;
		VREF(vp);
		fp->f_vnode = vp;
		fp->f_data = vp;
		fp->f_offset = 0;
		vput(tvp);
		VFS_UNLOCK_GIANT(vfslocked);
		goto unionread;
	}
	VOP_UNLOCK(vp, 0);
	VFS_UNLOCK_GIANT(vfslocked);
	*basep = loff;
	td->td_retval[0] = count - auio.uio_resid;
fail:
	fdrop(fp, td);
	return (error);
} 
