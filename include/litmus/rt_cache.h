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
	if (tsk_rt(t)->job_params.cache_state != s)
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
		TRACE("[ERROR] try to lock 0x%x on NO_CPU\n", cp_mask);
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
		TRACE("[ERROR] try to unlock 0x%x on NO_CPU\n", cp_mask);
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
 * 		   rt_param.scheduled_on must be setup
 * 		b) IF s == CACHE_WILL_CLEAR | CACHE_CLEARED
 * 		   rt_param.scheduled_on must NOT be cleared
 * 		   job.cache_partitions do not have to be cleared since
 * 		   cache_state can indicate that info is useless.
 * rt_domain_t.lock is grabbed by the caller
 */
static inline void 
set_cache_config(rt_domain_t *rt, struct task_struct *task, cache_state_t s)
{
	TRACE_TASK(task, "Before change cache_state rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
				rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);

	/* Check cache_state */
	if (s == CACHE_CLEARED)
		check_cache_state(task, CACHE_WILL_CLEAR);
	if (s == CACHE_IN_USE)
		check_cache_state(task, CACHE_WILL_USE);
	/* Change cache_state */
	set_cache_state(task, s);
	/* Change PL310 cache partition register */
	//TODO: Add Hyon's code
	if (s == CACHE_CLEARED)
		unlock_cache_partitions(tsk_rt(task)->scheduled_on,
				tsk_rt(task)->job_params.cache_partitions);
	if (s == CACHE_IN_USE)
		lock_cache_partitions(tsk_rt(task)->scheduled_on,
				tsk_rt(task)->job_params.cache_partitions);
	/* Change rt.used_cache_partitions if
 	 * s == CACHE_CLEARED : clear job.cache_partitions bits
 	 * s == CACHE_IN_USE  : set job.cache_partitions bits
 	 */
	if (s == CACHE_CLEARED)
		rt->used_cache_partitions &= 
			~(tsk_rt(task)->job_params.cache_partitions & CACHE_PARTITIONS_MASK);
	if (s == CACHE_IN_USE)
			rt->used_cache_partitions |=
		(tsk_rt(task)->job_params.cache_partitions & CACHE_PARTITIONS_MASK);

	TRACE_TASK(task, "After change cache_state rt.used_cp_mask=0x%x job.cp_mask=0x%x\n",
				rt->used_cache_partitions, tsk_rt(task)->job_params.cache_partitions);
}

#endif
