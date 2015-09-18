#ifndef LITMUS_RT_CACHE_H
#define LITMUS_RT_CACHE_H

#include <litmus/preempt.h>
#include <litmus/cache_proc.h>

#define TRACE_CACHE_STATE_CHANGE(x, y, task)				\
	TRACE_TASK(task, "job:%d cp_mask:0x%x %d(%s) -> %d(%s)\n",	\
		    tsk_rt(task)->job_params.job_no, 			\
			tsk_rt(task)->job_params.cache_partitions,	\
			(x), cache_state_name(x),					\
		    (y), cache_state_name(y))

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

/* lock_cache_partitions
 * lock cp_mask for cpu so that only cpu can use cp_mask
 * NOTE:
 * 1) rt.lock is grabbed by the caller so that
 *    scheduler on diff CPUs do not have race condition
 * 2) We have race condition when user write to /proc/sys
 *    As long as users do not write to /proc/sys, we are safe
 */
static inline void
lock_cache_partitions(int cpu, uint16_t cp_mask)
{
	if (cpu == NO_CPU)
	{
		TRACE("[BUG] try to lock 0x%x on NO_CPU\n", cp_mask);
	}
	__lock_cache_ways_to_cpu(cpu, cp_mask);
	return;
}

/* unlock_cache_partitions
 * unlock cp_mask for cpu so that other cpus can use cp_mask
 */
static inline void
unlock_cache_partitions(int cpu, uint16_t cp_mask)
{
	if (cpu == NO_CPU)
	{
		TRACE("[BUG] try to unlock 0x%x on NO_CPU\n", cp_mask);
	}
	__unlock_cache_ways_to_cpu(cpu);
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
static inline void 
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
				   ~(tsk_rt(task)->job_params.cache_partitions & CACHE_PARTITIONS_MASK));
		/* PL310 unlock cache
 		 * A task may be preempted when the task have been linked to a CPU but
 		 * have not been scheduled on the CPU */
		unlock_cache_partitions(tsk_rt(task)->linked_on,
				tsk_rt(task)->job_params.cache_partitions);
		rt->used_cache_partitions &= 
			~(tsk_rt(task)->job_params.cache_partitions & CACHE_PARTITIONS_MASK);
		/* Reset cp to 0 to indicate the cp are unlocked 
 		 * Have to reset, otherwise, we will clear unlocked cp when cache_state
 		 * changes from WILL_USE to WILL_CLEAR to CLEARED */
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
		lock_cache_partitions(tsk_rt(task)->linked_on,
				tsk_rt(task)->job_params.cache_partitions);
		rt->used_cache_partitions |=
			(tsk_rt(task)->job_params.cache_partitions & CACHE_PARTITIONS_MASK);
	}

	/* Change cache_state */
	set_cache_state(task, s);
//	TRACE_TASK(task, "After change cache_state rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
//				rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);
}

#endif
