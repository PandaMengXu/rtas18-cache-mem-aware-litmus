#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>

#include <litmus/litmus.h>
#include <litmus/jobs.h>
#include <litmus/sched_plugin.h>
#include <litmus/fp_common.h>
#include <litmus/sched_trace.h>
#include <litmus/trace.h>

#include <litmus/preempt.h>
#include <litmus/budget.h>

#include <litmus/rt_cache.h>

/* CPU cache status for all cache-aware scheduler */
DEFINE_PER_CPU(cpu_cache_entry_t, cpu_cache_entries);

/* task t cache_state should be s
 */
static inline void
check_cache_state(struct task_struct *t, cache_state_t s)
{
	if (!(tsk_rt(t)->job_params.cache_state & s))
	{
		TRACE_TASK(t, "[WARN] cache status %d(%s) should be %d(%s)\n",
				   tsk_rt(t)->job_params.cache_state,
				   cache_state_name(tsk_rt(t)->job_params.cache_state),
				   s, cache_state_name(s));
	}
}

/* set_cache_state
 * Change job.cache_state to new state
 */
static inline void
set_cache_state(struct task_struct *task, cache_state_t s)
{
	TRACE_CACHE_STATE_CHANGE(tsk_rt(task)->job_params.cache_state, s, task);
	tsk_rt(task)->job_params.cache_state = s;
}

/* input
 * cpu: the cpu to check
 * cp_mask: the cp_mask the cpu has
 **/
static inline void
check_cache_status_invariant(int cpu, uint32_t cp_mask)
{
	int i;
	cpu_cache_entry_t *cache_entry_tmp, *cache_entry;
	uint32_t used_cp;
	
	cache_entry = &per_cpu(cpu_cache_entries, cpu);
	for (i = 0; i < num_online_cpus(); i++)
	{
		cache_entry_tmp = &per_cpu(cpu_cache_entries, i);
		if (i != cpu && (cache_entry_tmp->used_cp & cp_mask))
		{
			TRACE("[BUG]Lock [P%d], Detect overlap CP: [P%d] used_cp:0x%x, [P%d] used_cp:0x%x (0x%x)\n",
				   cpu, i, cache_entry_tmp->used_cp, cpu, cache_entry->used_cp, cp_mask);
		}
        /* NB: TODO: Lets delay this sanity check to a later point. */
        /*
		if (__get_used_cache_ways_on_cpu(i, &used_cp))
		{
			TRACE("[ERROR] get_used_cache_ways_on_cpu %d fails\n", i);
		}
		if (used_cp != cache_entry_tmp->used_cp)
		{
			TRACE("[BUG] [P%d] cache_entry->used_cp(0x%x) != get_used_cache_ways_on_cpu->used_cp(0x%x)\n",
				   i, cache_entry_tmp->used_cp, used_cp);
		}
        */

	}
}

/* Flush a cache partition for a task tsk only when 
 * this cache partition was used by other tasks
 * Because the cache partitions have been reserved for
 * the task tsk before this function is called,
 * we don't need to grab lock for this since different 
 * tasks on different cores use different elements in rt->l2_cps */
void
selective_flush_cache_partitions(int cpu, uint32_t cp_mask, struct task_struct *tsk, rt_domain_t *rt)
{
	if (cp_mask != 0)
	{
		/* TODO: calculate cache ways to flush */
		uint32_t cp_mask_to_flush = 0;
		int i;
		for (i = 0; i < MAX_CACHE_PARTITIONS; i++)
		{
			if (cp_mask & (1 << i))
			{
				if (rt->l2_cps[i] != tsk->pid)
				{
					cp_mask_to_flush |= (1 << i);
					rt->l2_cps[i] = tsk->pid;
				}
			}
		}
		if (cp_mask_to_flush != 0)
#if defined(CONFIG_ARM)
			flush_cache_ways(cp_mask_to_flush);
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
            flush_cache_for_task(tsk);
#endif
	}
	else
	{
		TRACE("[BUG] lock cache partition 0 on cpu %d\n", cpu);
	}
}

/* lock_cache_partitions
 * lock cp_mask for cpu so that only cpu can use cp_mask
 * NOTE:
 * 1) rt.lock is grabbed by the caller so that
 *    scheduler on diff CPUs do not have race condition
 * 2) We have race condition when user write to /proc/sys
 *    As long as users do not write to /proc/sys, we are safe
 *
 * tsk: lock cache partition for task tsk
 */
void
lock_cache_partitions(int cpu, uint32_t cp_mask, struct task_struct *tsk, rt_domain_t *rt)
{
	cpu_cache_entry_t *cache_entry;
	//uint32_t used_cp;
    int ret = 0;

	if (cpu == NO_CPU)
	{
		TRACE("[BUG] try to lock 0x%x on NO_CPU\n", cp_mask);
	} else
	{
		cache_entry = &per_cpu(cpu_cache_entries, cpu);
		if (cache_entry->used_cp != 0)
		{
			TRACE("[BUG][P%d] has cp 0x%x (should be 0) locked before try to lock cp 0x%x\n",
				  cache_entry->cpu, cache_entry->used_cp, cp_mask);
		}
		///check_cache_status_invariant(cpu, cp_mask);
		cache_entry->used_cp = cp_mask;
	}
	
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    raw_spin_lock(&rt->cache_lock);
	ret = __lock_cache_ways_to_cpu(cpu, cp_mask);
	raw_spin_unlock(&rt->cache_lock);
#endif
    //if (ret)
	//{
	//	TRACE("[BUG][P%d] PL310 lock cache 0x%d fails\n",
	//		  cpu, cp_mask);
	//}
	//if (__get_used_cache_ways_on_cpu(cpu, &used_cp))
	//{
	//	TRACE("[ERROR] get_used_cache_ways_on_cpu(%d) fails\n", cpu);
	//}
	//if (used_cp != cp_mask)
	//{
	//	TRACE("[BUG][P%d] lock cache 0x%x but not in effect now, current cp=0x%x\n",
	//		  cpu, cp_mask, used_cp);
	//}

//	if (cp_mask != 0)
//	{
//		uint32_t cp_mask_to_flush = 0;
//		int i;
//		for (i = 0; i < MAX_CACHE_PARTITIONS; i++)
//		{
//			if (cp_mask & (1 << i))
//			{
//				if (rt->l2_cps[i] != tsk->pid)
//				{
//					cp_mask_to_flush |= (1 << i);
//					rt->l2_cps[i] = tsk->pid;
//				}
//			}
//		}
//		if (cp_mask_to_flush != 0)
//			flush_cache_ways(cp_mask_to_flush);
//	}
//	else
//	{
//		TRACE("[BUG] lock cache partition 0 on cpu %d\n", cpu);
//	}
	return;
}

/* unlock_cache_partitions
 * unlock cp_mask for cpu so that other cpus can use cp_mask
 */
void
unlock_cache_partitions(int cpu, uint32_t cp_mask, rt_domain_t *rt)
{
	cpu_cache_entry_t *cache_entry;
	//uint32_t used_cp;
    int ret = 0;

	if (cpu == NO_CPU)
	{
		TRACE("[BUG] try to unlock 0x%x on NO_CPU\n", cp_mask);
	} else
	{
		cache_entry = &per_cpu(cpu_cache_entries, cpu);
		if (cache_entry->used_cp != cp_mask)
		{
			TRACE("[BUG][P%d] try to unlock CP that has not been locked (locked: 0x%x, to unlock: 0x%x)\n",
				  cache_entry->cpu, cache_entry->used_cp, cp_mask);
		}
		///check_cache_status_invariant(cpu, cp_mask);
		cache_entry->used_cp = 0;
	}
    
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	raw_spin_lock(&rt->cache_lock);
	ret = __unlock_cache_ways_to_cpu(cpu);
	raw_spin_unlock(&rt->cache_lock);
#endif
    if (ret)
	{
		TRACE("[BUG][P%d] Unlock cache 0x%d fails\n",
			  cpu, cp_mask);
	}
	//if (__get_used_cache_ways_on_cpu(cpu, &used_cp))
	//{
	//	TRACE("[ERROR] get_used_cache_ways_on_cpu(%d)\n", cpu);
	//}
	//if (used_cp)
	//{
	//	TRACE("[BUG] Unlock cache partitions fails on P%d\n", cpu);
	//}


	//if (cp_mask != 0)
	//	flush_cache_ways(cp_mask);
	//else
	//{
	//	TRACE("[BUG] unlock cache partition 0 on cpu %d\n", cpu);
	//}
	return;
}

/* set_cache_config
 * Check task.cache_state is correct before change it
 * Change job.cache_state to new state
 * Change PL310 cache partition register
 * 		a) CACHE_IN_USE: lock job.cache_partitions on task.core
 * 		b) CACHE_CLEARED: unlock job.cache_partitions on task.core
 * Change rt.used_cache_partitions when 
 * 		a) new partitions are CACHE_IN_USE or old 
 * 		b) cache partitions are CACHE_CLEARED
 * NOTE:
 * 		a) IF s == CACHE_WILL_USE, before call this func
 * 		   job.cache_partitions must be setup 
 * 		   rt_param.linked_on must be setup
 * 		b) IF s == CACHE_WILL_CLEAR | CACHE_CLEARED
 * 		   rt_param.scheduled_on must NOT be cleared
 * 		   job.cache_partitions do not have to be cleared since
 * 		   cache_state can indicate that info is useless.
 * rt_domain_t.lock is grabbed by the caller
 */
void 
set_cache_config(rt_domain_t *rt, struct task_struct *task, cache_state_t s)
{
//	TRACE_TASK(task, "Before change cache_state rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
//				rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);
	
	/* Check cache_state */
	if (s == CACHE_CLEARED)
		check_cache_state(task, CACHE_WILL_CLEAR);
	if (s == CACHE_IN_USE)
		check_cache_state(task, CACHE_WILL_USE);
	if (s == CACHE_WILL_CLEAR)
		check_cache_state(task, CACHE_WILL_USE | CACHE_IN_USE);
	/* Clear job.cp if cache state CACHE_WILL_USE -> CACHE_WILL_CLEAR
 	 * job.cp indicate if cp have been lock 
 	 * job.cp != 0 only in CACHE_WILL_USE | CACHE_IN_USE 
 	 * NOTE: we lock/unlock cache at WILL_USE and WILL_CLEAR */
	//if ((tsk_rt(task)->job_params.cache_state & CACHE_WILL_USE) &&
	//	(s & (CACHE_WILL_CLEAR | CACHE_CLEARED)))
	//	tsk_rt(task)->job_params.cache_partitions = 0;
	
	/* Change PL310 cache partition register */
	//if (s == CACHE_CLEARED) /* Unlock cp earlier to avoid race condition */
	//if (s == CACHE_WILL_CLEAR)
	//	unlock_cache_partitions(tsk_rt(task)->scheduled_on,
	//			tsk_rt(task)->job_params.cache_partitions);
	//if (s == CACHE_IN_USE) /* Lock cp earlier to avoid race condition and avoid just preempted task to use the preempted cp */
	//if (s == CACHE_WILL_USE)
	//	lock_cache_partitions(tsk_rt(task)->linked_on,
	//			tsk_rt(task)->job_params.cache_partitions);
	/* Change rt.used_cache_partitions if
 	 * s is CACHE_WILL_CLEAR | CACHE_CLEARED : clear job.cache_partitions bits
 	 * s is CACHE_WILL_USE | CACHE_IN_USE  : set job.cache_partitions bits
 	 * We do not repeatly lock/unlock the cache for the same task
 	 */
	//if (s == CACHE_CLEARED)
	if (s == CACHE_WILL_CLEAR &&
		(tsk_rt(task)->job_params.cache_state & (CACHE_WILL_USE | CACHE_IN_USE)))
	{
		/* job.cp_mask should all in rt.used_cp_mask */
		if ((~rt->used_cache_partitions) & tsk_rt(task)->job_params.cache_partitions)
			TRACE_TASK(task, "[ERROR] Unlock a cp not used rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
					   rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);
		TRACE_TASK(task, "rt.used_cp=0x%x, job.cp=0x%x ~job.cp=0x%x\n",
				   rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions,
				   (~(tsk_rt(task)->job_params.cache_partitions) & CACHE_PARTITIONS_MASK));
		/* PL310 unlock cache
 		 * A task may be preempted when the task have been linked to a CPU but
 		 * have not been scheduled on the CPU */
        /* NB: set_cache_config function may likely be called with irq disabled
         *     Any callee from set_cache_config cannot depend on irq delivery
         *     Otherwise, deadlock will occur when irq delivery to the self CPU */
		unlock_cache_partitions(tsk_rt(task)->linked_on,
				tsk_rt(task)->job_params.cache_partitions, rt);
		rt->used_cache_partitions &= 
			(~(tsk_rt(task)->job_params.cache_partitions) & CACHE_PARTITIONS_MASK);
		/* Reset cp to 0 to indicate the cp are unlocked 
 		 * Have to reset, otherwise, we will clear unlocked cp when cache_state
 		 * changes from WILL_USE to WILL_CLEAR to CLEARED */
		tsk_rt(task)->job_params.cp_prev = tsk_rt(task)->job_params.cache_partitions;
		tsk_rt(task)->job_params.cache_partitions = 0;
	}
	//if (s == CACHE_IN_USE)
	if (s == CACHE_WILL_USE &&
		(tsk_rt(task)->job_params.cache_state & (CACHE_INIT | CACHE_WILL_CLEAR | CACHE_CLEARED)))
	{
		if (tsk_rt(task)->job_params.cache_partitions & rt->used_cache_partitions)
			TRACE_TASK(task, "[ERROR] Lock a cp already used rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
					   rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);
		/* PL310 lock cache */
        /* NB: set_cache_config function may likely be called with irq disabled */
		lock_cache_partitions(tsk_rt(task)->linked_on,
				tsk_rt(task)->job_params.cache_partitions, task, rt);
		rt->used_cache_partitions |=
			(tsk_rt(task)->job_params.cache_partitions & CACHE_PARTITIONS_MASK);
	}

	/* Change cache_state */
	set_cache_state(task, s);
//	TRACE_TASK(task, "After change cache_state rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
//				rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);
}

void wrmsrl_smp(void *data)
{
    wrmsrl(((msr_data_t *) data)->msr, ((msr_data_t *) data)->val);
}

void rdmsrl_smp(void *data)
{
    rdmsrl(((msr_data_t *) data)->msr, ((msr_data_t *) data)->val);
}

/**
 *  set cbm i register to val on (v)cpu i of domU
 *  Number of VCPUs is not limited as long as physical CPU number <= CBM Reg number
 **/
int rtxen_cat_set_cbm(int cpu, uint32_t val)
{
    msr_data_t data;

    /* Check CBM value to set is in valid range */
    if ( hweight32(val) < MSR_IA32_CBM_MIN_NUM_BITS_RTXEN ||
         hweight32(val) > MSR_IA32_CBM_LENGTH_RTXEN )
    {
        printk("[RTXEN ERR] set_cbm val hweight32(cbm:0x%d) >= %d\n",
                val, MSR_IA32_CBM_MIN_NUM_BITS_RTXEN);
        return -EINVAL;
    }

    dbprintk("[RTXEN INFO] set_cbm: CPU %d cbm to 0x%x\n", cpu, val);
    data.msr = MSR_IA32_COS_REG_BASE + cpu;
    data.val = val & MSR_IA32_CBM_MASK;
    smp_call_function_single(cpu, wrmsrl_smp, &data, 1);
    /* Do not print if correct to avoid flood the output */
    //printk("set_cpu_cbm: [P%d] wrmsr 0x%x => 0x%lx (0x%x)\n",
    //            cpu, data.msr, data.val, val);

    return 0;
}


int _update_cbm_reg(struct task_struct *next)
{
    int ret = 0; 

    /* Note: We CAN also use scheduled_on or linked_on to determine
     * where next is running because LITMUS scheduler uses them to
     * determine where the task is running; but the next has to be RT task;
     * otherwise, scheduled_on and linked_on will always be 0
     * */
    /*MX: need sync cp param between task_params and job_params */
    /*
    printk("[RTXEN DEBUG] next->scheduled_on=%d, next->linked=%d, task_cpu=%d\n",
            tsk_rt(next)->scheduled_on, tsk_rt(next)->linked_on, task_cpu(next));
    */
    ret = rtxen_cat_set_cbm(task_cpu(next), tsk_rt(next)->task_params.set_of_cp_init);

    return ret; 
}
