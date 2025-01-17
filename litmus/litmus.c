/*
 * litmus.c -- Implementation of the LITMUS syscalls,
 *             the LITMUS intialization code,
 *             and the procfs interface..
 */
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/sysrq.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/reboot.h>
#include <linux/stop_machine.h>
#include <linux/sched/rt.h>
#include <linux/rwsem.h>
#include <linux/time.h>
#include <linux/spinlock.h>

#include <litmus/litmus.h>
#include <litmus/bheap.h>
#include <litmus/trace.h>
#include <litmus/rt_domain.h>
#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/clock.h>

#include <asm/cacheflush.h>

#include <litmus/cache_proc.h>
#include <litmus/rt_cache.h>

#ifdef CONFIG_SCHED_CPU_AFFINITY
#include <litmus/affinity.h>
#endif

#ifdef CONFIG_SCHED_LITMUS_TRACEPOINT
#define CREATE_TRACE_POINTS
#include <trace/events/litmus.h>
#endif

/* Number of RT tasks that exist in the system */
atomic_t rt_task_count 		= ATOMIC_INIT(0);

spinlock_t cos_lock[MSR_IA32_COS_REG_NUM];

#ifdef CONFIG_RELEASE_MASTER
/* current master CPU for handling timer IRQs */
atomic_t release_master_cpu = ATOMIC_INIT(NO_CPU);
#endif
atomic_t ftrace_sched_only_record_ddl_miss = ATOMIC_INIT(0);

static struct kmem_cache * bheap_node_cache;
extern struct kmem_cache * release_heap_cache;

struct bheap_node* bheap_node_alloc(int gfp_flags)
{
	return kmem_cache_alloc(bheap_node_cache, gfp_flags);
}

void bheap_node_free(struct bheap_node* hn)
{
	kmem_cache_free(bheap_node_cache, hn);
}

struct release_heap* release_heap_alloc(int gfp_flags);
void release_heap_free(struct release_heap* rh);

/**
 * Get the quantum alignment as a cmdline option.
 * Default is staggered quanta, as this results in lower overheads.
 */
static bool aligned_quanta = 0;
module_param(aligned_quanta, bool, 0644);

u64 cpu_stagger_offset(int cpu)
{
	u64 offset = 0;

	if (!aligned_quanta) {
		offset = LITMUS_QUANTUM_LENGTH_NS;
		do_div(offset, num_possible_cpus());
		offset *= cpu;
	}
	return offset;
}

/*
 * sys_set_task_rt_param
 * @pid: Pid of the task which scheduling parameters must be changed
 * @param: New real-time extension parameters such as the execution cost and
 *         period
 * Syscall for manipulating with task rt extension params
 * Returns EFAULT  if param is NULL.
 *         ESRCH   if pid is not corrsponding
 *	           to a valid task.
 *	   EINVAL  if either period or execution cost is <=0
 *	   EPERM   if pid is a real-time task
 *	   0       if success
 *
 * Only non-real-time tasks may be configured with this system call
 * to avoid races with the scheduler. In practice, this means that a
 * task's parameters must be set _before_ calling sys_prepare_rt_task()
 *
 * find_task_by_vpid() assumes that we are in the same namespace of the
 * target.
 */
asmlinkage long sys_set_rt_task_param(pid_t pid, struct rt_task __user * param)
{
	struct rt_task tp;
	struct task_struct *target;
	int retval = -EINVAL;
	int to_flush_task = 0; /* delay the cache flush after irq is unmasked */

	printk("Setting up rt task parameters for process %d.\n", pid);

	if (pid < 0 || param == 0) {
		goto out;
	}
	if (copy_from_user(&tp, param, sizeof(tp))) {
		retval = -EFAULT;
		goto out;
	}

	/* Task search and manipulation must be protected */
	read_lock_irq(&tasklist_lock);
	if (!(target = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}

    /**
     * Meng: We allow parameter changes when a task has already been real-time task
     * We do NOT have any protection for the data race on the real-time parameter of
     * the task.
     * If the real-time field that is related to the real-time scheduling decision is changed,
     * it will cause *undefined* behavior for the scheduler behavior!
     * THIS IS A DIRTY HACK for the paper experiment evaluation to
     * show dynamic cache management benefit!
     * We need to be able to change a task cache partition setting when the task is running
     */
#if 0
	if (is_realtime(target)) {
		/* The task is already a real-time task.
		 * We cannot not allow parameter changes at this point.
		 */
		retval = -EBUSY;
		goto out_unlock;
	}
#endif

	/* set relative deadline to be implicit if left unspecified */
	if (tp.relative_deadline == 0)
		tp.relative_deadline = tp.period;

	if (tp.exec_cost <= 0)
		goto out_unlock;
	if (tp.period <= 0)
		goto out_unlock;
	if (min(tp.relative_deadline, tp.period) < tp.exec_cost) /*density check*/
	{
		printk(KERN_INFO "litmus: real-time task %d rejected "
		       "because task density > 1.0\n", pid);
		goto out_unlock;
	}
	if (tp.cls != RT_CLASS_HARD &&
	    tp.cls != RT_CLASS_SOFT &&
	    tp.cls != RT_CLASS_BEST_EFFORT)
	{
		printk(KERN_INFO "litmus: real-time task %d rejected "
				 "because its class is invalid\n", pid);
		goto out_unlock;
	}
	if (tp.budget_policy != NO_ENFORCEMENT &&
	    tp.budget_policy != QUANTUM_ENFORCEMENT &&
	    tp.budget_policy != PRECISE_ENFORCEMENT)
	{
		printk(KERN_INFO "litmus: real-time task %d rejected "
		       "because unsupported budget enforcement policy "
		       "specified (%d)\n",
		       pid, tp.budget_policy);
		goto out_unlock;
	}
	if (tp.num_cache_partitions < 0)
		goto out_unlock;

    if (tp.page_colors != 0)
    {
        printk(KERN_INFO "litmus: page_color(0x%lx) should only be set with PAGE_COLORS env\n",
               tp.page_colors);
        goto out_unlock;
    }

    printk(KERN_INFO "litmus: scheduler %s\n", litmus->plugin_name);
    if ( !strcmp(litmus->plugin_name, "GSN-FPCA2") ||
         !strcmp(litmus->plugin_name, "GSN-NPFPCA") )
	{
		if (tp.set_of_cp_init != 0)
		{
			printk(KERN_ERR "litmus: set_of_cp_init 0x%x must be 0 for cache-aware schedulers\n",
				   tp.set_of_cp_init);
			printk(KERN_ERR "litmus: cache-aware schedulers dynamically decide tasks' cache partitions\n");
			goto out_unlock;
		}
		/* flush cache for cache-aware tasks
         * NB: We cannot flush cache for cache-aware scheduler which may flush cache inside scheduler 
         * Reason: This function is called with tasklist_lock held, which serializes schedule()
         *     When cache-aware scheduler is invoked, it will grab tasklist_lock. 
         *     You have to be VERY CAREFULY about the lock order; otherwise, deadlock occurs
         *     Since cache-aware scheduler will flush the task's cache before the task is
         *     scheduled to execute, we do NOT have to take the trouble here! */
        //flush_cache_for_task(target); /* Think super hard before uncomment this line! */
        printk(KERN_ERR "litmus: try to flush under cache-aware scheduler\n");
	} else { /* Non-cache-aware schedulers */
		/* Configure a specific cache area for a task under non-cache-aware scheduler */
		if (tp.set_of_cp_init != 0)
		{
			if (hweight_long(tp.set_of_cp_init) < MSR_IA32_CBM_MIN_NUM_BITS_RTXEN ||
	    		hweight_long(tp.set_of_cp_init) > MSR_IA32_CBM_LENGTH_RTXEN)
			{
				printk(KERN_ERR "litmus: set_of_cp_init 0x%x is invalid\n",
					tp.set_of_cp_init);
				goto out_unlock;
			}
			/* flush cache for non-cache-aware tasks */
        	//flush_cache_for_task(target); /* flush task here will cause fatal page fault. Why?! */
			to_flush_task = 1;
        	printk(KERN_ERR "litmus: try to flush under non-cache-aware scheduler\n");
		}
	}

	target->rt_param.task_params = tp;

	retval = 0;
      out_unlock:
	read_unlock_irq(&tasklist_lock);
      out:
	if ( to_flush_task == 1 )
    {
        _update_cbm_reg(target);
    	flush_cache_for_task(target);
    }
	return retval;
}

/*
 * Getter of task's RT params
 *   returns EINVAL if param or pid is NULL
 *   returns ESRCH  if pid does not correspond to a valid task
 *   returns EFAULT if copying of parameters has failed.
 *
 *   find_task_by_vpid() assumes that we are in the same namespace of the
 *   target.
 */
asmlinkage long sys_get_rt_task_param(pid_t pid, struct rt_task __user * param)
{
	int retval = -EINVAL;
	struct task_struct *source;
	struct rt_task lp;
	if (param == 0 || pid < 0)
		goto out;
	read_lock(&tasklist_lock);
	if (!(source = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}
	lp = source->rt_param.task_params;
	read_unlock(&tasklist_lock);
	/* Do copying outside the lock */
	retval =
	    copy_to_user(param, &lp, sizeof(lp)) ? -EFAULT : 0;
	return retval;
      out_unlock:
	read_unlock(&tasklist_lock);
      out:
	return retval;

}

/*
 * sys_set_rt_task_cps
 * @pid: Pid of the task which cache partitions (cps) parameters must be changed
 * @param: New cps parameters
 * Syscall for manipulating with task rt extension params
 * Returns EFAULT  if param is NULL.
 *         ESRCH   if pid is not corrsponding
 *	           to a valid task.
 *	   EINVAL  if either period or execution cost is <=0
 *	   EPERM   if pid is a real-time task
 *	   0       if success
 *
 * WARNING:
 * This is the LITMUS design
 * Only non-real-time tasks may be configured with this system call
 * to avoid races with the scheduler. In practice, this means that a
 * task's parameters must be set _before_ calling sys_prepare_rt_task()
 * We allow a task parameter to be modified in real-time mode.
 * This may leave the possibility of race condition.
 *
 * find_task_by_vpid() assumes that we are in the same namespace of the
 * target.
 */
asmlinkage long sys_set_rt_task_cps(pid_t pid, struct rt_cache __user * param)
{
	struct rt_cache newcps;
	struct task_struct *target;
	int retval = -EINVAL;
	int to_flush_task = 0; /* delay the cache flush after irq is unmasked */

	dbprintk("Setting up rt task parameters for process %d.\n", pid);

	if (pid < 0 || param == 0) {
		goto out;
	}
	if (copy_from_user(&newcps, param, sizeof(newcps))) {
		retval = -EFAULT;
		goto out;
	}

	/* Task search and manipulation must be protected */
	read_lock_irq(&tasklist_lock);
	if (!(target = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}

    /**
     * Meng: We allow parameter changes when a task has already been real-time task
     * We do NOT have any protection for the data race on the real-time parameter of
     * the task.
     * If the real-time field that is related to the real-time scheduling decision is changed,
     * it will cause *undefined* behavior for the scheduler behavior!
     * THIS IS A DIRTY HACK for the paper experiment evaluation to
     * show dynamic cache management benefit!
     * We need to be able to change a task cache partition setting when the task is running
     */
#if 0
	if (is_realtime(target)) {
		/* The task is already a real-time task.
		 * We cannot not allow parameter changes at this point.
		 */
		retval = -EBUSY;
		goto out_unlock;
	}
#endif
    /* TODO: Change constant to macro */
    if ( hweight_long(newcps.set_of_cps) < 2 || hweight_long(newcps.set_of_cps) > 20 )
    {
        printk(KERN_WARNING "litmus: newcps.set_of_cps (0x%x) must be [2, 20]\n", newcps.set_of_cps);
		goto out_unlock;
    }

    if ( newcps.flush == 1 )
    {
        dbprintk(KERN_INFO "litmus: scheduler %s\n", litmus->plugin_name);
        if ( !strcmp(litmus->plugin_name, "GSN-FPCA2") ||
             !strcmp(litmus->plugin_name, "GSN-NPFPCA") )
        {
            if (newcps.set_of_cps != 0)
            {
                printk(KERN_ERR "User should never manually set cache partitions for tasks under cache-aware schedulers\n");
                printk(KERN_ERR "litmus: set_of_cps 0x%x must be 0 for cache-aware schedulers\n",
                       newcps.set_of_cps);
                printk(KERN_ERR "litmus: cache-aware schedulers dynamically decide tasks' cache partitions\n");
                goto out_unlock;
            }
            /* flush cache for cache-aware tasks
             * NB: We cannot flush cache for cache-aware scheduler which may flush cache inside scheduler 
             * Reason: This function is called with tasklist_lock held, which serializes schedule()
             *     When cache-aware scheduler is invoked, it will grab tasklist_lock. 
             *     You have to be VERY CAREFULY about the lock order; otherwise, deadlock occurs
             *     Since cache-aware scheduler will flush the task's cache before the task is
             *     scheduled to execute, we do NOT have to take the trouble here! */
            //flush_cache_for_task(target); /* Think super hard before uncomment this line! */
            dbprintk(KERN_ERR "litmus: try to flush under cache-aware scheduler\n");
        } else { /* Non-cache-aware schedulers */
            /* Configure a specific cache area for a task under non-cache-aware scheduler */
            if (newcps.set_of_cps != 0)
            {
                //flush_cache_for_task(target); /* flush task here will cause fatal page fault. Why?! */
                to_flush_task = 1;
                dbprintk(KERN_ERR "litmus: try to flush under non-cache-aware scheduler\n");
            }
        }
    }

	target->rt_param.task_params.set_of_cp_init = newcps.set_of_cps;

	retval = 0;
      out_unlock:
	read_unlock_irq(&tasklist_lock);
      out:
	if ( to_flush_task == 1 )
    {
        _update_cbm_reg(target);
    	flush_cache_for_task(target);
    }
	return retval;
}

/*
 * Getter of task's RT cache parameter
 *   returns EINVAL if param or pid is NULL
 *   returns ESRCH  if pid does not correspond to a valid task
 *   returns EFAULT if copying of parameters has failed.
 *
 *   find_task_by_vpid() assumes that we are in the same namespace of the
 *   target.
 */
asmlinkage long sys_get_rt_task_cps(pid_t pid, struct rt_cache __user * param)
{
	int retval = -EINVAL;
	struct task_struct *source;
	struct rt_task lp;
	if (param == 0 || pid < 0)
		goto out;
	read_lock(&tasklist_lock);
	if (!(source = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}
	lp = source->rt_param.task_params;
	read_unlock(&tasklist_lock);
	/* Do copying outside the lock */
	retval =
	    copy_to_user(&param->set_of_cps, &lp.set_of_cp_init, sizeof(lp.set_of_cp_init)) ? -EFAULT : 0;
	return retval;
      out_unlock:
	read_unlock(&tasklist_lock);
      out:
	return retval;
}

/*
 * Getter of RT params of a job
 *   returns EINVAL if param or pid is NULL
 *   returns ESRCH  if pid does not correspond to a valid task
 *   returns EFAULT if copying of parameters has failed.
 *
 *   find_task_by_vpid() assumes that we are in the same namespace of the
 *   target.
 */
asmlinkage long sys_get_rt_job_param(pid_t pid, struct rt_job __user * param)
{
	int retval = -EINVAL;
	struct task_struct *source;
	struct rt_job lp;
	if (param == 0 || pid < 0)
		goto out;
	read_lock(&tasklist_lock);
	if (!(source = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}
	lp = source->rt_param.job_params;
	read_unlock(&tasklist_lock);
	/* Do copying outside the lock */
	retval =
	    copy_to_user(param, &lp, sizeof(lp)) ? -EFAULT : 0;
	return retval;
      out_unlock:
	read_unlock(&tasklist_lock);
      out:
	return retval;

}

asmlinkage long sys_mark_event(pid_t pid, int __user event_id, int __user data)
{
	int retval = -EINVAL;
	struct task_struct *source;
	if (pid < 0)
		goto out;
	read_lock(&tasklist_lock);
	if (!(source = find_task_by_vpid(pid))) {
		retval = -ESRCH;
		goto out_unlock;
	}
	read_unlock(&tasklist_lock);
	TRACE_TASK(source, "[MARK] %lld event:%d, data:%d\n",
			   litmus_clock(), event_id, data);
	return retval;
      out_unlock:
	read_unlock(&tasklist_lock);
      out:
	return retval;

}

/*
 *	This is the crucial function for periodic task implementation,
 *	It checks if a task is periodic, checks if such kind of sleep
 *	is permitted and calls plugin-specific sleep, which puts the
 *	task into a wait array.
 *	returns 0 on successful wakeup
 *	returns EPERM if current conditions do not permit such sleep
 *	returns EINVAL if current task is not able to go to sleep
 */
asmlinkage long sys_complete_job(void)
{
	int retval = -EPERM;
	if (!is_realtime(current)) {
		retval = -EINVAL;
		goto out;
	}
	/* Task with negative or zero period cannot sleep */
	if (get_rt_period(current) <= 0) {
		retval = -EINVAL;
		goto out;
	}
	/* The plugin has to put the task into an
	 * appropriate queue and call schedule
	 */
	retval = litmus->complete_job();
      out:
	return retval;
}

/*	This is an "improved" version of sys_complete_job that
 *      addresses the problem of unintentionally missing a job after
 *      an overrun.
 *
 *	returns 0 on successful wakeup
 *	returns EPERM if current conditions do not permit such sleep
 *	returns EINVAL if current task is not able to go to sleep
 */
asmlinkage long sys_wait_for_job_release(unsigned int job)
{
	int retval = -EPERM;
	if (!is_realtime(current)) {
		retval = -EINVAL;
		goto out;
	}

	/* Task with negative or zero period cannot sleep */
	if (get_rt_period(current) <= 0) {
		retval = -EINVAL;
		goto out;
	}

	retval = 0;

	/* first wait until we have "reached" the desired job
	 *
	 * This implementation has at least two problems:
	 *
	 * 1) It doesn't gracefully handle the wrap around of
	 *    job_no. Since LITMUS is a prototype, this is not much
	 *    of a problem right now.
	 *
	 * 2) It is theoretically racy if a job release occurs
	 *    between checking job_no and calling sleep_next_period().
	 *    A proper solution would requiring adding another callback
	 *    in the plugin structure and testing the condition with
	 *    interrupts disabled.
	 *
	 * FIXME: At least problem 2 should be taken care of eventually.
	 */
	while (!retval && job > current->rt_param.job_params.job_no)
		/* If the last job overran then job <= job_no and we
		 * don't send the task to sleep.
		 */
		retval = litmus->complete_job();
      out:
	return retval;
}

/*	This is a helper syscall to query the current job sequence number.
 *
 *	returns 0 on successful query
 *	returns EPERM if task is not a real-time task.
 *      returns EFAULT if &job is not a valid pointer.
 */
asmlinkage long sys_query_job_no(unsigned int __user *job)
{
	int retval = -EPERM;
	if (is_realtime(current))
		retval = put_user(current->rt_param.job_params.job_no, job);

	return retval;
}

/* sys_null_call() is only used for determining raw system call
 * overheads (kernel entry, kernel exit). It has no useful side effects.
 * If ts is non-NULL, then the current Feather-Trace time is recorded.
 */
asmlinkage long sys_null_call(cycles_t __user *ts)
{
	long ret = 0;
	cycles_t now;

	if (ts) {
		now = litmus_get_cycles();
		ret = put_user(now, ts);
	}
	else
		flush_cache_all();

	return ret;
}

asmlinkage long sys_flush_cache(struct timespec __user *start, struct timespec __user *end)
{
    long ret = 0;
    struct timespec ts1, ts2;
    
    dbprintk("sys_flush_cache is called\n");
    getnstimeofday(&ts1);
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    flush_cache_for_task(current);
#endif
    getnstimeofday(&ts2);

    if (start != NULL) {
        copy_to_user(start, &ts1, sizeof(struct timespec));
    }

    if (end != NULL) {
        copy_to_user(end, &ts2, sizeof(struct timespec));
    }

    return ret;
}

asmlinkage long sys_set_cos_ipi(uint32_t cos_id, uint32_t val,
                                cycles_t __user *usr_start, cycles_t __user *usr_end)
{
    int cpu;
    msr_data_t data;
    cycles_t start, end;

    if ( cos_id < 0 || cos_id >= MSR_IA32_COS_REG_NUM )
    {
        printk("cos_id:%d is out of range [0, %d)\n",
                cos_id, MSR_IA32_COS_REG_NUM);
        return -EINVAL;
    }

    dbprintk("sys_set_cos_ipi is called cos_id=%d val=%x\n", cos_id, val);

    cpu = cos_id;
    data.msr = MSR_IA32_COS_REG_BASE + cos_id;
    data.val = val & MSR_IA32_CBM_MASK;
    start = litmus_get_cycles();
    smp_call_function_single(cpu, wrmsrl_smp, &data, 1);
    end = litmus_get_cycles();

	if (copy_to_user(usr_start, &start, sizeof(start)))
    {
        printk("copy_to_user for start fails\n");
        return -EFAULT;
    }
	if (copy_to_user(usr_end, &end, sizeof(end)))
    {
        printk("copy_to_user for end fails\n");
        return -EFAULT;
    }

    return 0;
}

asmlinkage long sys_set_cos_lock(uint32_t cos_id, uint32_t val,
                                 cycles_t __user *usr_start, cycles_t __user *usr_end)
{
    int cpu;
    msr_data_t data;
    cycles_t start, end;

    if ( cos_id < 0 || cos_id >= MSR_IA32_COS_REG_NUM )
    {
        printk("cos_id:%d is out of range [0, %d)\n",
                cos_id, MSR_IA32_COS_REG_NUM);
        return -EINVAL;
    }

    dbprintk("sys_set_cos_lock is called cos_id=%d val=%x\n", cos_id, val);
    cpu = cos_id;
    data.msr = MSR_IA32_COS_REG_BASE + cos_id;
    data.val = val & MSR_IA32_CBM_MASK;

    start = litmus_get_cycles();
    /* grab lock before change the cos register */
    //write_lock(&cos_lock[cos_id]);
    spin_lock(&cos_lock[cos_id]);
    wrmsrl_smp(&data);
    spin_unlock(&cos_lock[cos_id]);
    //write_unlock(&cos_lock[cos_id]);
    end = litmus_get_cycles();

	if (copy_to_user(usr_start, &start, sizeof(start)))
    {
        printk("copy_to_user for start fails\n");
        return -EFAULT;
    }
	if (copy_to_user(usr_end, &end, sizeof(end)))
    {
        printk("copy_to_user for end fails\n");
        return -EFAULT;
    }

    return 0;
}

asmlinkage long sys_rt_wrmsr(int cpu, uint32_t msr, uint64_t val)
{
    msr_data_t data;

    dbprintk("sys_rt_wrmsr is called cpu=%d msr=0x%08x val=0x%016lx\n", cpu, msr, (long long) val);

    data.msr = msr;
    data.val = val;
    smp_call_function_single(cpu, wrmsrl_smp, &data, 1);

    return 0;
}

asmlinkage long sys_rt_rdmsr(int cpu, uint32_t msr, uint64_t __user *val)
{
    msr_data_t data;

    dbprintk("sys_rt_wrmsr is called cpu=%d msr=0x%08x val=0x%016lx\n", cpu, msr, val);

    data.msr = msr;
    data.val = val;
    smp_call_function_single(cpu, rdmsrl_smp, &data, 1);

	if (copy_to_user(val, &data.val, sizeof(data.val)))
    {
        printk("copy_to_user for val fails\n");
        return -EFAULT;
    }

    return 0;   
}

asmlinkage long sys_rt_wbinvd(void)
{
    dbprintk("sys_rt_wbinvd is called\n");
    __asm__ ("wbinvd");   
    return 0;
}

/* p is a real-time task. Re-init its state as a best-effort task. */
static void reinit_litmus_state(struct task_struct* p, int restore)
{
	struct rt_task  user_config = {};
	void*  ctrl_page     = NULL;

	if (restore) {
		/* Safe user-space provided configuration data.
		 * and allocated page. */
		user_config = p->rt_param.task_params;
		ctrl_page   = p->rt_param.ctrl_page;
	}

	/* We probably should not be inheriting any task's priority
	 * at this point in time.
	 */
	WARN_ON(p->rt_param.inh_task);

	/* Cleanup everything else. */
	memset(&p->rt_param, 0, sizeof(p->rt_param));

	/* Restore preserved fields. */
	if (restore) {
		p->rt_param.task_params = user_config;
		p->rt_param.ctrl_page   = ctrl_page;
	}
}

long litmus_admit_task(struct task_struct* tsk)
{
	long retval = 0;

	BUG_ON(is_realtime(tsk));

	tsk_rt(tsk)->heap_node = NULL;
	tsk_rt(tsk)->rel_heap = NULL;

	if (get_rt_relative_deadline(tsk) == 0 ||
	    get_exec_cost(tsk) >
			min(get_rt_relative_deadline(tsk), get_rt_period(tsk)) ) {
		TRACE_TASK(tsk,
			"litmus admit: invalid task parameters "
			"(e = %lu, p = %lu, d = %lu)\n",
			get_exec_cost(tsk), get_rt_period(tsk),
			get_rt_relative_deadline(tsk));
		retval = -EINVAL;
		goto out;
	} else {
		TRACE_TASK(tsk,
			"litmus admit: valid task parameters "
			"(e = %lu, p = %lu, d = %lu cp=%d)\n",
			get_exec_cost(tsk), get_rt_period(tsk),
			get_rt_relative_deadline(tsk),
			tsk_rt(tsk)->task_params.num_cache_partitions);
	}

	INIT_LIST_HEAD(&tsk_rt(tsk)->list);

	/* allocate heap node for this task */
	tsk_rt(tsk)->heap_node = bheap_node_alloc(GFP_ATOMIC);
	tsk_rt(tsk)->rel_heap = release_heap_alloc(GFP_ATOMIC);

	if (!tsk_rt(tsk)->heap_node || !tsk_rt(tsk)->rel_heap) {
		printk(KERN_WARNING "litmus: no more heap node memory!?\n");

		retval = -ENOMEM;
		goto out;
	} else {
		bheap_node_init(&tsk_rt(tsk)->heap_node, tsk);
	}

	preempt_disable();

	retval = litmus->admit_task(tsk);

	if (!retval) {
		sched_trace_task_name(tsk);
		sched_trace_task_param(tsk);
		atomic_inc(&rt_task_count);
	}

	preempt_enable();

out:
	if (retval) {
		if (tsk_rt(tsk)->heap_node)
			bheap_node_free(tsk_rt(tsk)->heap_node);
		if (tsk_rt(tsk)->rel_heap)
			release_heap_free(tsk_rt(tsk)->rel_heap);
	}
	return retval;
}

void litmus_clear_state(struct task_struct* tsk)
{
    BUG_ON(bheap_node_in_heap(tsk_rt(tsk)->heap_node));
    bheap_node_free(tsk_rt(tsk)->heap_node);
    release_heap_free(tsk_rt(tsk)->rel_heap);

    atomic_dec(&rt_task_count);
    reinit_litmus_state(tsk, 1);
}

/* called from sched_setscheduler() */
void litmus_exit_task(struct task_struct* tsk)
{
	if (is_realtime(tsk)) {
		sched_trace_task_completion(tsk, 1);

		litmus->task_exit(tsk);
	}
}

static DECLARE_RWSEM(plugin_switch_mutex);

void litmus_plugin_switch_disable(void)
{
	down_read(&plugin_switch_mutex);
}

void litmus_plugin_switch_enable(void)
{
	up_read(&plugin_switch_mutex);
}

static int do_plugin_switch(void *_plugin)
{
	int ret;
	struct sched_plugin* plugin = _plugin;

	/* don't switch if there are active real-time tasks */
	if (atomic_read(&rt_task_count) == 0) {
		printk(KERN_INFO "Deactive LITMUS^RT plugin %s...\n", plugin->plugin_name);
		ret = litmus->deactivate_plugin();
		if (0 != ret)
			goto out;
		printk(KERN_INFO "Active LITMUS^RT plugin %s...\n", plugin->plugin_name);
		ret = plugin->activate_plugin();
		if (0 != ret) {
			printk(KERN_INFO "Can't activate %s (%d).\n",
			       plugin->plugin_name, ret);
			plugin = &linux_sched_plugin;
		}

		printk(KERN_INFO "Switching to LITMUS^RT plugin %s.\n", plugin->plugin_name);
		litmus = plugin;
	} else
		ret = -EBUSY;
out:
	return ret;
}

/* Switching a plugin in use is tricky.
 * We must watch out that no real-time tasks exists
 * (and that none is created in parallel) and that the plugin is not
 * currently in use on any processor (in theory).
 */
int switch_sched_plugin(struct sched_plugin* plugin)
{
	int err;
	struct domain_proc_info* domain_info;

	BUG_ON(!plugin);

	if (atomic_read(&rt_task_count) == 0) {
		down_write(&plugin_switch_mutex);

		deactivate_domain_proc();

		err =  stop_machine(do_plugin_switch, plugin, NULL);

		if(!litmus->get_domain_proc_info(&domain_info))
			activate_domain_proc(domain_info);

		up_write(&plugin_switch_mutex);
		return err;
	} else
		return -EBUSY;
}

/* Called upon fork.
 * p is the newly forked task.
 */
void litmus_fork(struct task_struct* p)
{
	if (is_realtime(p)) {
		/* clean out any litmus related state, don't preserve anything */
		reinit_litmus_state(p, 0);
		/* Don't let the child be a real-time task.  */
		p->sched_reset_on_fork = 1;
	} else
		/* non-rt tasks might have ctrl_page set */
		tsk_rt(p)->ctrl_page = NULL;

	/* od tables are never inherited across a fork */
	p->od_table = NULL;
}

/* Called upon execve().
 * current is doing the exec.
 * Don't let address space specific stuff leak.
 */
void litmus_exec(void)
{
	struct task_struct* p = current;

	if (is_realtime(p)) {
		WARN_ON(p->rt_param.inh_task);
		if (tsk_rt(p)->ctrl_page) {
			free_page((unsigned long) tsk_rt(p)->ctrl_page);
			tsk_rt(p)->ctrl_page = NULL;
		}
	}
}

/* Called when dead_tsk is being deallocated
 */
void exit_litmus(struct task_struct *dead_tsk)
{
	/* We also allow non-RT tasks to
	 * allocate control pages to allow
	 * measurements with non-RT tasks.
	 * So check if we need to free the page
	 * in any case.
	 */
	if (tsk_rt(dead_tsk)->ctrl_page) {
		TRACE_TASK(dead_tsk,
			   "freeing ctrl_page %p\n",
			   tsk_rt(dead_tsk)->ctrl_page);
		free_page((unsigned long) tsk_rt(dead_tsk)->ctrl_page);
	}

	/* Tasks should not be real-time tasks any longer at this point. */
	BUG_ON(is_realtime(dead_tsk));
}

void litmus_do_exit(struct task_struct *exiting_tsk)
{
	/* This task called do_exit(), but is still a real-time task. To avoid
	 * complications later, we force it to be a non-real-time task now. */

	struct sched_param param = { .sched_priority = MAX_RT_PRIO - 1 };

	TRACE_TASK(exiting_tsk, "exiting, demoted to SCHED_FIFO\n");
	sched_setscheduler_nocheck(exiting_tsk, SCHED_FIFO, &param);
}

void litmus_dealloc(struct task_struct *tsk)
{
	/* tsk is no longer a real-time task */
	TRACE_TASK(tsk, "Deallocating real-time task data\n");
	litmus->task_cleanup(tsk);
	litmus_clear_state(tsk);
}

#ifdef CONFIG_MAGIC_SYSRQ
int sys_kill(int pid, int sig);

static void sysrq_handle_kill_rt_tasks(int key)
{
	struct task_struct *t;
	read_lock(&tasklist_lock);
	for_each_process(t) {
		if (is_realtime(t)) {
			sys_kill(t->pid, SIGKILL);
		}
	}
	read_unlock(&tasklist_lock);
}

static struct sysrq_key_op sysrq_kill_rt_tasks_op = {
	.handler	= sysrq_handle_kill_rt_tasks,
	.help_msg	= "quit-rt-tasks(X)",
	.action_msg	= "sent SIGKILL to all LITMUS^RT real-time tasks",
};
#endif

extern struct sched_plugin linux_sched_plugin;

static int litmus_shutdown_nb(struct notifier_block *unused1,
				unsigned long unused2, void *unused3)
{
	/* Attempt to switch back to regular Linux scheduling.
	 * Forces the active plugin to clean up.
	 */
	if (litmus != &linux_sched_plugin) {
		int ret = switch_sched_plugin(&linux_sched_plugin);
		if (ret) {
			printk("Auto-shutdown of active Litmus plugin failed.\n");
		}
	}
	return NOTIFY_DONE;
}

static struct notifier_block shutdown_notifier = {
	.notifier_call = litmus_shutdown_nb,
};

#if defined(CONFIG_CPU_V7) && !defined(CONFIG_HW_PERF_EVENTS)
static void __init litmus_enable_perfcounters_v7(void *_ignore)
{
	u32 enable_val = 0;

	/* disable performance monitoring */
	asm volatile("mcr p15, 0, %0, c9, c12, 0" : : "r" (0x00000006));

	/* disable all events */
	asm volatile("mcr p15, 0, %0, c9, c12, 2" : : "r" (0xffffffff));

	/* write 1 to enable user-mode access to the performance counter */
	asm volatile("mcr p15, 0, %0, c9, c14, 0" : : "r" (1));

	/* disable counter overflow interrupts (just in case) */
	asm volatile("mcr p15, 0, %0, c9, c14, 2" : : "r" (0x8000000f));

	/* select event zero */
	asm volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (0));

	/* count cycles in the selected event zero */
	asm volatile("mcr p15, 0, %0, c9, c13, 1" : : "r" (0x00000011));

	enable_val |= 1;	/* bit 1 enables the counters */
	enable_val |= 2;	/* resets event counters to zero */
	enable_val |= 4;	/* resets cycle counter to zero */
	//enable_val |= 8;	/* enable "by 64" divider for CCNT. */
	
	/* performance monitor control register: enable all counters */
	asm volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(enable_val));

	/* enables counters (cycle counter and event 1) */
        asm volatile("mcr p15, 0, %0, c9, c12, 1" : : "r"(0x80000001));
}

static void __init litmus_enable_perfcounters(void)
{
	litmus_enable_perfcounters_v7(NULL);
	smp_call_function(litmus_enable_perfcounters_v7, NULL, 0);
}
#endif

static int __init _init_litmus(void)
{
    int i;

	/*      Common initializers,
	 *      mode change lock is used to enforce single mode change
	 *      operation.
	 */
	printk("Starting LITMUS^RT kernel\n");

	register_sched_plugin(&linux_sched_plugin);

	bheap_node_cache    = KMEM_CACHE(bheap_node, SLAB_PANIC);
	release_heap_cache = KMEM_CACHE(release_heap, SLAB_PANIC);

#ifdef CONFIG_MAGIC_SYSRQ
	/* offer some debugging help */
	if (!register_sysrq_key('x', &sysrq_kill_rt_tasks_op))
		printk("Registered kill rt tasks magic sysrq.\n");
	else
		printk("Could not register kill rt tasks magic sysrq.\n");
#endif

	init_litmus_proc();

#ifdef CONFIG_SCHED_CPU_AFFINITY
	init_topology();
#endif

	register_reboot_notifier(&shutdown_notifier);

#if defined(CONFIG_CPU_V7) && !defined(CONFIG_HW_PERF_EVENTS)	
	litmus_enable_perfcounters();
#endif

    /*Initialize spin lock*/
    for ( i = 0; i < MSR_IA32_COS_REG_NUM; i++ )
    {
        spin_lock_init(&cos_lock[i]);
        printk("cos_lokc[%d] is initialized\n", i);
    }
	
	return 0;
}

static void _exit_litmus(void)
{
	unregister_reboot_notifier(&shutdown_notifier);

	exit_litmus_proc();
	kmem_cache_destroy(bheap_node_cache);
	kmem_cache_destroy(release_heap_cache);
}

module_init(_init_litmus);
module_exit(_exit_litmus);
