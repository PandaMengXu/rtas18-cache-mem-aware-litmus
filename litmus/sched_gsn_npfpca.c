/*
 * litmus/sched_gsn_npfpca.c
 *
 * Implementation of the non-preemptive cache-aware global fixed priority
 * scheduling algorithm, proposed by Nan Guan in EMSOFT09
 * Copy from litmus/sched_gsn_npfpca.c
 *
 * This version uses the simple approach and serializes all scheduling
 * decisions by the use of a queue lock. This is probably not the
 * best way to do it, but it should suffice for now.
 */

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

#include <litmus/bheap.h>

#ifdef CONFIG_SCHED_CPU_AFFINITY
#include <litmus/affinity.h>
#endif

/* to set up domain/cpu mappings */
#include <litmus/litmus_proc.h>

#include <linux/module.h>

#include <litmus/rt_cache.h>

/* Overview of GSN-NPFPCA operations.
 *
 * For a detailed explanation of GSN-NPFPCA have a look at the FMLP paper. This
 * description only covers how the individual operations are implemented in
 * LITMUS.
 *
 * link_task_to_cpu(T, cpu) 	- Low-level operation to update the linkage
 *                                structure (NOT the actually scheduled
 *                                task). If there is another linked task To
 *                                already it will set To->linked_on = NO_CPU
 *                                (thereby removing its association with this
 *                                CPU). However, it will not requeue the
 *                                previously linked task (if any). It will set
 *                                T's state to not completed and check whether
 *                                it is already running somewhere else. If T
 *                                is scheduled somewhere else it will link
 *                                it to that CPU instead (and pull the linked
 *                                task to cpu). T may be NULL.
 *
 * unlink(T)			- Unlink removes T from all scheduler data
 *                                structures. If it is linked to some CPU it
 *                                will link NULL to that CPU. If it is
 *                                currently queued in the gsnnpfpca queue it will
 *                                be removed from the rt_domain. It is safe to
 *                                call unlink(T) if T is not linked. T may not
 *                                be NULL.
 *
 * requeue(T)			- Requeue will insert T into the appropriate
 *                                queue. If the system is in real-time mode and
 *                                the T is released already, it will go into the
 *                                ready queue. If the system is not in
 *                                real-time mode is T, then T will go into the
 *                                release queue. If T's release time is in the
 *                                future, it will go into the release
 *                                queue. That means that T's release time/job
 *                                no/etc. has to be updated before requeu(T) is
 *                                called. It is not safe to call requeue(T)
 *                                when T is already queued. T may not be NULL.
 *
 * gsnnpfpca_job_arrival(T)	- This is the catch all function when T enters
 *                                the system after either a suspension or at a
 *                                job release. It will queue T (which means it
 *                                is not safe to call gsnnpfpca_job_arrival(T) if
 *                                T is already queued) and then check whether a
 *                                preemption is necessary. If a preemption is
 *                                necessary it will update the linkage
 *                                accordingly and cause scheduled to be called
 *                                (either with an IPI or need_resched). It is
 *                                safe to call gsnnpfpca_job_arrival(T) if T's
 *                                next job has not been actually released yet
 *                                (releast time in the future). T will be put
 *                                on the release queue in that case.
 *
 * job_completion(T)		- Take care of everything that needs to be done
 *                                to prepare T for its next release and place
 *                                it in the right queue with
 *                                gsnnpfpca_job_arrival().
 *
 *
 * When we now that T is linked to CPU then link_task_to_cpu(NULL, CPU) is
 * equivalent to unlink(T). Note that if you unlink a task from a CPU none of
 * the functions will automatically propagate pending task from the ready queue
 * to a linked task. This is the job of the calling function ( by means of
 * __take_ready).
 */

#define SCHED_INIT					0 /* init of cpu_entry_t.flag */
#define SCHED_FORCE_SCHED_OUT		1 /* sched the current task out of the cpu */
/* cpu_entry_t - maintain the linked and scheduled state
 */
typedef struct  {
	int 			cpu;
	struct task_struct*	preempting; /* only RT tasks, RT task that preempt a RT task on a core */
	struct task_struct*	linked;		/* only RT tasks */
	struct task_struct*	scheduled;	/* only RT tasks */
	struct bheap_node*	hn;
} cpu_entry_t;
DEFINE_PER_CPU(cpu_entry_t, gsnnpfpca_cpu_entries);

cpu_entry_t* gsnnpfpca_cpus[NR_CPUS];

DECLARE_PER_CPU(cpu_cache_entry_t, cpu_cache_entries);

/* the cpus queue themselves according to priority in here */
static struct bheap_node gsnnpfpca_heap_node[NR_CPUS];
static struct bheap      gsnnpfpca_cpu_heap;

rt_domain_t gsnnpfpca;
#define gsnnpfpca_lock (gsnnpfpca.ready_lock)
#define gsnnpfpca_cache_lock (gsnnpfpca.cache_lock)

static struct task_struct standby_tasks;
static cpu_entry_t* standby_cpus[NR_CPUS];

/* Uncomment this if you want to see all scheduling decisions in the
 * TRACE() log. */
#define WANT_ALL_SCHED_EVENTS
#define WANT_ALL_CACHE_EVENTS

static int cpu_lower_prio(struct bheap_node *_a, struct bheap_node *_b)
{
	cpu_entry_t *a, *b;
	a = _a->value;
	b = _b->value;
	/* Note that a and b are inverted: we want the lowest-priority CPU at
	 * the top of the heap.
	 */
	return fp_higher_prio(b->linked, a->linked);
}

/* update_cpu_position - Move the cpu entry to the correct place to maintain
 *                       order in the cpu queue. Caller must hold gsnnpfpca lock.
 */
static void update_cpu_position(cpu_entry_t *entry)
{
	if (likely(bheap_node_in_heap(entry->hn)))
		bheap_delete(cpu_lower_prio, &gsnnpfpca_cpu_heap, entry->hn);
	bheap_insert(cpu_lower_prio, &gsnnpfpca_cpu_heap, entry->hn);
}

/* caller must hold gsnnpfpca lock */
static cpu_entry_t* lowest_prio_cpu(void)
{
	struct bheap_node* hn;
	hn = bheap_peek(cpu_lower_prio, &gsnnpfpca_cpu_heap);
	return hn->value;
}

static void remove_cpu(cpu_entry_t *entry)
{
	if (likely(bheap_node_in_heap(entry->hn)))
		bheap_delete(cpu_lower_prio, &gsnnpfpca_cpu_heap, entry->hn);
}

static void insert_cpu(cpu_entry_t *entry)
{
	bheap_insert(cpu_lower_prio, &gsnnpfpca_cpu_heap, entry->hn);
}

/* link_task_to_cpu - Update the link of a CPU.
 *                    Handles the case where the to-be-linked task is already
 *                    scheduled on a different CPU.
 */
static noinline void link_task_to_cpu(struct task_struct* linked,
				      cpu_entry_t *entry)
{
	cpu_entry_t *sched;
	struct task_struct* tmp;
	int on_cpu;

	BUG_ON(linked && !is_realtime(linked));

	/* Currently linked task is set to be unlinked. */
	if (entry->linked) {
		entry->linked->rt_param.linked_on = NO_CPU;
	}

	/* Link new task to CPU. */
	if (linked) {
		/* handle task is already scheduled somewhere! */
		on_cpu = linked->rt_param.scheduled_on;
		if (on_cpu != NO_CPU) {
			sched = &per_cpu(gsnnpfpca_cpu_entries, on_cpu);
			/* this should only happen if not linked already */
			BUG_ON(sched->linked == linked);

			/* If we are already scheduled on the CPU to which we
			 * wanted to link, we don't need to do the swap --
			 * we just link ourselves to the CPU and depend on
			 * the caller to get things right.
			 */
			if (entry != sched) {
				TRACE_TASK(linked,
					   "already scheduled on %d, updating link.\n",
					   sched->cpu);
				tmp = sched->linked;
				linked->rt_param.linked_on = sched->cpu;
				sched->linked = linked;
				update_cpu_position(sched);
				linked = tmp;
			}
		}
		if (linked) /* might be NULL due to swap */
			linked->rt_param.linked_on = entry->cpu;
	}
	entry->linked = linked;
#ifdef WANT_ALL_SCHED_EVENTS
	if (linked)
		TRACE_TASK(linked, "linked to %d.\n", entry->cpu);
	else
		TRACE("NULL linked to %d.\n", entry->cpu);
#endif
	update_cpu_position(entry);
}

/* unlink - Make sure a task is not linked any longer to an entry
 *          where it was linked before. Must hold gsnnpfpca_lock.
 */
static noinline void unlink(struct task_struct* t)
{
	cpu_entry_t *entry;

	if (t->rt_param.linked_on != NO_CPU) {
		/* unlink */
		entry = &per_cpu(gsnnpfpca_cpu_entries, t->rt_param.linked_on);
		t->rt_param.linked_on = NO_CPU;
		link_task_to_cpu(NULL, entry);
	} else if (is_queued(t)) {
		/* This is an interesting situation: t is scheduled,
		 * but was just recently unlinked.  It cannot be
		 * linked anywhere else (because then it would have
		 * been relinked to this CPU), thus it must be in some
		 * queue. We must remove it from the list in this
		 * case.
		 */
		remove(&gsnnpfpca, t);
	}
}


/* preempt - force a CPU to reschedule
 */
static void preempt(cpu_entry_t *entry)
{
	preempt_if_preemptable(entry->scheduled, entry->cpu);
}

/* requeue - Put an unlinked task into gsn-fpca domain.
 *           Caller must hold gsnnpfpca_lock.
 */
static noinline void requeue(struct task_struct* task)
{
	BUG_ON(!task);
	/* sanity check before insertion */
	BUG_ON(is_queued(task));

	if (is_early_releasing(task) || is_released(task, litmus_clock()))
		__add_ready(&gsnnpfpca, task);
	else {
		/* it has got to wait */
		add_release(&gsnnpfpca, task);
	}
}

#ifdef CONFIG_SCHED_CPU_AFFINITY
static cpu_entry_t* gsnnpfpca_get_nearest_available_cpu(cpu_entry_t *start)
{
	cpu_entry_t *affinity;

	get_nearest_available_cpu(affinity, start, gsnnpfpca_cpu_entries,
#ifdef CONFIG_RELEASE_MASTER
			gsnnpfpca.release_master
#else
			NO_CPU
#endif
			);

	return(affinity);
}
#endif

/* Check if top task in ready_queue can preempt a CPU
 * Remove the top task from ready_queue if preemption occurs  */
static inline int check_for_preemptions_helper(void)
{
	rt_domain_t *rt = &gsnnpfpca;
	struct task_struct *task;
	int num_used_cache_partitions = 0;
	int cpu_ok = 0;
	int cache_ok = 0;
	uint16_t cp_mask_to_use = 0; /* mask of cache partitions the task to use */
	int num_cp_to_use = 0;
	struct task_struct preempted_tasks;
	cpu_entry_t *cpu_to_preempt = NULL;
	int i;
	struct list_head *iter, *tmp;
	int has_preemption = 0;

	INIT_LIST_HEAD(&tsk_rt(&preempted_tasks)->standby_list);

	/*TODO: Assume no priority inversion first! */
	task = __peek_ready(&gsnnpfpca);

	if (!task) {
		TRACE_TASK(task, "No ready RT tasks\n");
		goto out;
	}

	TRACE_TASK(task, "check_for_preemptions...\n");

	/* Check if local cpu is idle first */
	cpu_to_preempt = &__get_cpu_var(gsnnpfpca_cpu_entries);
    BUG_ON(!cpu_to_preempt);

	if (task && !cpu_to_preempt->linked) {
		cpu_ok = 1;
		cpu_to_preempt = cpu_to_preempt;
		TRACE_TASK(task, "linking to local CPU %d to avoid IPI if cache is enough\n", cpu_to_preempt->cpu);
	}

	/* Check if cache and cpu is available */
	num_used_cache_partitions =
		count_set_bits(rt->used_cache_partitions & CACHE_PARTITIONS_MASK);
	TRACE_TASK(task, "Attempt to preempt, num_used_cache_partitions=%d, used_cp_mask=0x%x, task.num_cp=%d\n",
			   num_used_cache_partitions, rt->used_cache_partitions, tsk_rt(task)->task_params.num_cache_partitions);
	if (MAX_NUM_CACHE_PARTITIONS - num_used_cache_partitions
		>= tsk_rt(task)->task_params.num_cache_partitions)
	{
		cpu_entry_t* entry = NULL;
		struct task_struct* cur = NULL;
		/* Enough idle cache partitions */
		cache_ok = 1;
		cp_mask_to_use = 0;
		for(i = 0; i < MAX_NUM_CACHE_PARTITIONS; i++)
		{
			if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
				break;
			if (!(rt->used_cache_partitions & (1<<i) & CACHE_PARTITIONS_MASK))
			{
				if (cp_mask_to_use & (1<<i) & CACHE_PARTITIONS_MASK)
					TRACE_TASK(task, "[BUG] cp_mask_to_use=0x%x double set i=%d\n",
							   cp_mask_to_use, i);
				cp_mask_to_use |= (1<<i) & CACHE_PARTITIONS_MASK;
				num_cp_to_use += 1;
			}
		}
		/* Find the lowest priority CPU to preempt */
		entry = lowest_prio_cpu();
		cur = entry->linked;

		if (!cur || !is_realtime(cur) || fp_higher_prio(task, cur))
		{
			if (!cpu_ok)
			{
				cpu_ok = 1;
				cpu_to_preempt = entry;
			}
		}
		TRACE_TASK(task, "Enough idle cache, cache_ok=%d, cpu_ok=%d, cp_mask_to_use=0x%x, cpu_to_preempt=%d\n",
				   cache_ok, cpu_ok, cp_mask_to_use, cpu_to_preempt->cpu);
	}

	/* If preemptible, link task to preempted cpu, preempt preempted_tasks*/
	if ( !cache_ok || !cpu_ok )
	{
		TRACE_TASK(task, "Cannot preempt, cache_ok=%d, cpu_ok=%d, rt.used_cp_mask=0x%x, need %d cps\n",
				   cache_ok, cpu_ok, rt->used_cache_partitions, tsk_rt(task)->task_params.num_cache_partitions);
		has_preemption = 0;
		goto out;
	}
	/* Preempt preempted tasks */
	BUG_ON(!cpu_to_preempt);
	/* Must take_ready before we requeue any task */
	has_preemption = 1;
	task = __take_ready(&gsnnpfpca);
	BUG_ON(!task);
	/* Requeue preempted task and preempt the cpu_to_preempt */
	if (cpu_to_preempt->linked && is_realtime(cpu_to_preempt->linked))
	{
		if (requeue_preempted_job(cpu_to_preempt->linked))
			requeue(cpu_to_preempt->linked);
		/* update global view of cache partitions */
		set_cache_config(rt, cpu_to_preempt->linked, CACHE_WILL_CLEAR);
	}

	/* Set up the preempting task and invoke schedule on preempted CPU */
	/* Always link preempting task to cpu_to_preempt */
	link_task_to_cpu(task, cpu_to_preempt);
	if (count_set_bits(cp_mask_to_use) != tsk_rt(task)->task_params.num_cache_partitions)
	{
		TRACE_TASK(task, "[BUG] cp_mask_to_use=0x%x bits num != task.num_cp %d\n",
				   cp_mask_to_use, tsk_rt(task)->task_params.num_cache_partitions);
	}
	tsk_rt(task)->job_params.cache_partitions = (cp_mask_to_use & CACHE_PARTITIONS_MASK);
	set_cache_config(rt, task, CACHE_WILL_USE);
	TRACE_TASK(task, "To preempt CPU %d, cache_ok=%d, cpu_ok=%d, job.cp_mask=0x%x, rt.used_cp_mask=0x%x\n",
			   cpu_to_preempt->cpu, cache_ok, cpu_ok, tsk_rt(task)->job_params.cache_partitions,
			   rt->used_cache_partitions);
	preempt(cpu_to_preempt);
 out:
	return has_preemption;
}

/* check_for_preemptions for all possible CPUs for gFPca */
static void check_for_preemptions(void)
{
	int i = 0;
	int has_preemption = 0;

	for (i = 0; i <= NR_CPUS + 1; i++)
	{
		has_preemption = check_for_preemptions_helper();
		if (has_preemption == 0)
			break;
	}

	if (i == NR_CPUS + 1)
	{
		TRACE("[BUG] ready_queue is not sorted properly.\n");
	}

	return;
}

/* gsnnpfpca_job_arrival: task is either resumed or released
 * We do not need to clear cache first at job arrival
 * Job arrival occurs only when previous job completion occurs,
 * which has set cache state to CACHE_WILL_CLEAR already
 */
static noinline void gsnnpfpca_job_arrival(struct task_struct* task)
{
	BUG_ON(!task);

	TRACE_TASK(task, "gsnnpfpca_job_arrival %s/%d/%d\n",
			   task->comm, task->pid,
			   tsk_rt(task)->job_params.job_no);
	requeue(task);
	check_for_preemptions();
}

static void gsnnpfpca_release_jobs(rt_domain_t* rt, struct bheap* tasks)
{
	unsigned long flags;

	TRACE("gsnnpfpca_release_jobs\n");
	raw_spin_lock_irqsave(&gsnnpfpca_lock, flags);

	__merge_ready(rt, tasks);
	check_for_preemptions();

	raw_spin_unlock_irqrestore(&gsnnpfpca_lock, flags);
}

/* caller holds gsnnpfpca_lock */
static noinline void job_completion(struct task_struct *t, int forced)
{
	rt_domain_t *rt = &gsnnpfpca;
	BUG_ON(!t);

	sched_trace_task_completion(t, forced);

	TRACE_TASK(t, "job_completion(). release cp_mask=0x%x, current used_cp_mask=0x%x\n",
			   tsk_rt(t)->job_params.cache_partitions, rt->used_cache_partitions);

	/* set flags */
	tsk_rt(t)->completed = 0;
	//set_cache_config(rt, t, CACHE_CLEARED);
	/* prepare for next period */
	prepare_for_next_period(t);
	if (is_early_releasing(t) || is_released(t, litmus_clock()))
		sched_trace_task_release(t);
	/* unlink */
	unlink(t);
	/* requeue
	 * But don't requeue a blocking task. */
	if (is_running(t))
		gsnnpfpca_job_arrival(t);
}

void gsnnpfpca_dump_cpus()
{
	int i;
	cpu_entry_t *entry = NULL;
	struct task_struct *ltask, *stask;

	for (i = 0; i < NR_CPUS; i++)
	{
		entry = gsnnpfpca_cpus[i];
		ltask = entry->linked;
		stask = entry->scheduled;
		if (ltask)
		{
			TRACE_TASK(ltask, "[DUMP] P%d ltask job.cp=0x%x t.num_cp=%d, cache_state=%d(%s)\n",
					   i, tsk_rt(ltask)->job_params.cache_partitions,
					   tsk_rt(ltask)->task_params.num_cache_partitions,
					   tsk_rt(ltask)->job_params.cache_state,
					   cache_state_name(tsk_rt(ltask)->job_params.cache_state));
		}
		if (stask)
		{
			TRACE_TASK(stask, "[DUMP] P%d stask job.cp=0x%x t.num_cp=%d, cache_state=%d(%s)\n",
					   i, tsk_rt(stask)->job_params.cache_partitions,
					   tsk_rt(stask)->task_params.num_cache_partitions,
					   tsk_rt(stask)->job_params.cache_state,
					   cache_state_name(tsk_rt(stask)->job_params.cache_state));
		}
	}
}

/* gsnnpfpca_check_sched_invariant
 * Check sched invariant at end of gsnnpfpca_schedule
 * gsnnpfpca.lock is grabbed by caller
 * Invariant: At the end of schedule() on a CPU,
 * the current linked task on the CPU should NOT be preemptable
 * by the top task in ready_queue
 */
void gsnnpfpca_check_sched_invariant()
{
	int i;
	cpu_entry_t *entry = NULL;
	struct task_struct *task = NULL;
	struct task_struct *qtask = NULL;
	struct task_struct *preempted_task = NULL;
	rt_domain_t *rt = &gsnnpfpca;
	int num_used_cp = 0;
	int num_avail_cp = 0;
	int cpu_ok = 0;
	int preempted_cpu = -1;

	qtask = __peek_ready(&gsnnpfpca);
	/* No ready RT task */
	if (!qtask)
		return;

	/* Top ready task has higher priority? */
	entry = &__get_cpu_var(gsnnpfpca_cpu_entries);
	task = entry->linked;
	if (fp_higher_prio(qtask, task))
	{
		cpu_ok = 1;
		preempted_task = task;
		preempted_cpu = entry->cpu;
	}

	num_used_cp =
        count_set_bits(rt->used_cache_partitions & CACHE_PARTITIONS_MASK);
	num_avail_cp = MAX_NUM_CACHE_PARTITIONS - num_used_cp;
	for (i = 0; i < NR_CPUS; i++)
	{
		entry = gsnnpfpca_cpus[i];
		/* entry may have picked a task but not schedule yet */
		task = entry->linked;
		if (!task || !is_realtime(task))
		{
			continue;
		}
		if (fp_higher_prio(qtask, task))
		{
			if (tsk_rt(task)->job_params.cache_state & (CACHE_WILL_USE | CACHE_IN_USE))
				num_avail_cp += tsk_rt(task)->task_params.num_cache_partitions;
		}
	}

	if (cpu_ok && 
		num_avail_cp >= tsk_rt(qtask)->task_params.num_cache_partitions)
	{
		if (preempted_task && is_realtime(preempted_task))
			TRACE_TASK(qtask, "[ERROR] can preempt %s/%d/%d on P%d rt.cp=0x%x qtask.num_cp=%d\n",
				   preempted_task->comm, preempted_task->pid,
				   tsk_rt(preempted_task)->job_params.job_no, preempted_cpu,
				   rt->used_cache_partitions, tsk_rt(qtask)->task_params.num_cache_partitions);
		if (preempted_task && !is_realtime(preempted_task))
			TRACE_TASK(qtask, "[ERROR] can preempt %s/%d on P%d rt.cp=0x%x qtask.num_cp=%d\n",
				   preempted_task->comm, preempted_task->pid,
				   preempted_cpu,
				   rt->used_cache_partitions, tsk_rt(qtask)->task_params.num_cache_partitions);
		if (!preempted_task)
			TRACE_TASK(qtask, "[ERROR] can preempt NULL on P%d rt.cp=0x%x qtask.num_cp=%d\n",
				   preempted_cpu,
				   rt->used_cache_partitions, tsk_rt(qtask)->task_params.num_cache_partitions);
		gsnnpfpca_dump_cpus();
	}

	return;
}

/* Getting schedule() right is a bit tricky. schedule() may not make any
 * assumptions on the state of the current task since it may be called for a
 * number of reasons. The reasons include a scheduler_tick() determined that it
 * was necessary, because sys_exit_np() was called, because some Linux
 * subsystem determined so, or even (in the worst case) because there is a bug
 * hidden somewhere. Thus, we must take extreme care to determine what the
 * current state is.
 *
 * The CPU could currently be scheduling a task (or not), be linked (or not).
 *
 * The following assertions for the scheduled task could hold:
 *
 *  - !is_running(scheduled)        // the job blocks
 *	- scheduled->timeslice == 0	// the job completed (forcefully)
 *	- is_completed()		// the job completed (by syscall)
 * 	- linked != scheduled		// we need to reschedule (for any reason)
 * 	- is_np(scheduled)		// rescheduling must be delayed,
 *					   sys_exit_np must be requested
 *
 * Any of these can occur together.
 */
static struct task_struct* gsnnpfpca_schedule(struct task_struct * prev)
{
	rt_domain_t *rt = &gsnnpfpca;
	cpu_entry_t* entry = &__get_cpu_var(gsnnpfpca_cpu_entries);
	int out_of_time, sleep, preempt, np, exists, blocks, finish, prev_cache_state;
	struct task_struct* next = NULL;
	cache_state_t cache_state_prev;

#ifdef CONFIG_RELEASE_MASTER
	/* Bail out early if we are the release master.
	 * The release master never schedules any real-time tasks.
	 */
	if (unlikely(gsnnpfpca.release_master == entry->cpu)) {
		sched_state_task_picked();
		return NULL;
	}
#endif

	raw_spin_lock(&gsnnpfpca_lock);

	/* sanity checking */
	BUG_ON(entry->scheduled && entry->scheduled != prev);
	BUG_ON(entry->scheduled && !is_realtime(prev));
	BUG_ON(is_realtime(prev) && !entry->scheduled);

	/* (0) Determine state */
	exists      = entry->scheduled != NULL;
	blocks      = exists && !is_running(entry->scheduled);
	out_of_time = exists && budget_enforced(entry->scheduled)
		&& budget_exhausted(entry->scheduled);
	np 	    = exists && is_np(entry->scheduled);
	sleep	    = exists && is_completed(entry->scheduled);
	preempt     = entry->scheduled != entry->linked;
	cache_state_prev = tsk_rt(prev)->job_params.cache_state;
	finish 	= 0;
	if (is_realtime(prev))
	{
		prev_cache_state = tsk_rt(prev)->job_params.cache_state;
	} else
	{
		prev_cache_state = CACHE_INVALID;
	}

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "invoked gsnnpfpca_schedule.\n");
#endif

	if (exists)
		TRACE_TASK(prev,
			   "blocks:%d out_of_time:%d np:%d sleep:%d preempt:%d "
			   "state:%d sig:%d cp:0x%x rt.cp:0x%x\n",
			   blocks, out_of_time, np, sleep, preempt,
			   prev->state, signal_pending(prev),
			   tsk_rt(prev)->job_params.cache_partitions,
			   rt->used_cache_partitions);
	if (entry->linked && preempt)
		TRACE_TASK(prev, "will be preempted by %s/%d\n",
			   entry->linked->comm, entry->linked->pid);
	/* If a task blocks we have no choice but to reschedule.
	 */
	if (blocks)
	{
		set_cache_config(rt, entry->scheduled, CACHE_WILL_CLEAR);
		unlink(entry->scheduled);
	}

	/* Request a sys_exit_np() call if we would like to preempt but cannot.
	 * We need to make sure to update the link structure anyway in case
	 * that we are still linked. Multiple calls to request_exit_np() don't
	 * hurt.
	 */
	if (np && (out_of_time || preempt || sleep)) {
		/* Always clear cache before unlink */
		set_cache_config(rt, entry->scheduled, CACHE_WILL_CLEAR);
		unlink(entry->scheduled);
		request_exit_np(entry->scheduled);
	}

	/* Any task that is preemptable and either exhausts its execution
	 * budget or wants to sleep completes. We may have to reschedule after
	 * this. Don't do a job completion if we block (can't have timers running
	 * for blocked jobs).
	 */
	if (exists && !np && (out_of_time || sleep) && !blocks)
	{
		finish = 1;
		set_cache_config(rt, entry->scheduled, CACHE_WILL_CLEAR);
		job_completion(entry->scheduled, !sleep);
	}

	/* Be preempted */
	if (exists && !np && !(out_of_time || sleep) && !blocks &&
	    entry->linked != entry->scheduled) {
		set_cache_config(rt, entry->scheduled, CACHE_WILL_CLEAR);
	}

	/* Link pending task if we became unlinked.
 	 * But do not link if the core is preempted only via cache 
	 */
	if (!entry->linked)
	{
		/* scheduled RT task is preempted due to cache if 
 		 * is_realtime(entry->scheduled) &&
 		 * in CACHE_WILL_CLEAR state; The preempted RT task will be handled
 		 * in the rest of this function.
 		 * otherwise, check if another RT task can run on the CPU
 		 * Note: Even when we consider priority inversion,
 		 * 		 logic here is still correct.
 		 */
		if (!exists || !is_realtime(entry->scheduled))
		{
			check_for_preemptions();
		}
	}

	/* The final scheduling decision. Do we need to switch for some reason?
	 * If linked is different from scheduled, then select linked as next.
	 */
	if ((!np || blocks) &&
	    entry->linked != entry->scheduled) {
		if (entry->scheduled) {
			/* We unlock cache at CACHE_WILL_CLEAR state */
			//set_cache_config(rt, entry->scheduled, CACHE_WILL_CLEAR);
			/* not gonna be scheduled soon */
			entry->scheduled->rt_param.scheduled_on = NO_CPU;
			/* No need to set job_params.cache_partitions to 0 because cache_state has indicated that. */
			TRACE_TASK(entry->scheduled, "scheduled_on = NO_CPU, rt->used_cp_mask=0x%x should exclude job.cp_mask=0x%x\n",
					   rt->used_cache_partitions, entry->scheduled->rt_param.job_params.cache_partitions);
			/* Trace when preempted via cache by another CPU */
			if (!blocks && !entry->linked && !finish 
				&& !(prev_cache_state & CACHE_INIT))
			{
				if (!entry->preempting)
				{
					TRACE_TASK(entry->scheduled, "[BUG] preempted by NULL.\n");
				} else
				{
					TRACE_TASK(entry->scheduled, "preempted by %s/%d/%d due to cache preemption\n",
				   	       entry->preempting->comm, entry->preempting->pid,
						   tsk_rt(entry->preempting)->job_params.job_no);
					entry->preempting = NULL;
				}
			}
		}
		/* Schedule a linked job? */
		if (entry->linked) {
			entry->linked->rt_param.scheduled_on = entry->cpu;
			next = entry->linked;
			set_cache_config(rt, next, CACHE_WILL_USE);
			TRACE_TASK(next, "scheduled_on = P%d, rt.used_cp_mask=0x%x should include job.cp_mask=0x%x\n",
					   smp_processor_id(), rt->used_cache_partitions, tsk_rt(next)->job_params.cache_partitions);
		}
	} else
		/* Only override Linux scheduler if we have a real-time task
		 * scheduled that needs to continue.
		 */
		if (exists)
			next = prev;

	/* Task next job execute immediately after previous job finish
 	 * entry->scheduled is still the task but we are at next job 
 	 * need to update the cache state status to CACHE_IN_USE because
 	 * rt.cache_partitions were cleared when previous job finish */
	if (entry->scheduled && is_realtime(entry->scheduled))
	{
		if (tsk_rt(entry->scheduled)->job_params.cache_state & CACHE_WILL_USE)
			set_cache_config(rt, entry->scheduled, CACHE_IN_USE);
		if (tsk_rt(entry->scheduled)->job_params.cache_state & CACHE_WILL_CLEAR)
			set_cache_config(rt, entry->scheduled, CACHE_CLEARED);
	}
	if (entry->linked && is_realtime(entry->linked))
	{
		if (tsk_rt(entry->linked)->job_params.cache_state & CACHE_WILL_USE)
			set_cache_config(rt, entry->linked, CACHE_IN_USE);
		if (tsk_rt(entry->linked)->job_params.cache_state & CACHE_WILL_CLEAR)
			set_cache_config(rt, entry->linked, CACHE_CLEARED);
	}

	sched_state_task_picked();

	/* Check correctness of scheduler
  	 * NOTE: TODO: avoid such check in non-debug mode */
	//gsnnpfpca_check_sched_invariant();

	raw_spin_unlock(&gsnnpfpca_lock);

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(next, "gsnnpfpca_lock released\n");

	if (next)
		TRACE_TASK(next, "scheduled at %llu\n", litmus_clock());
	else if (exists && !next)
		TRACE("becomes idle at %llu.\n", litmus_clock());
	else
		TRACE("idle stays idle at %llu.\n", litmus_clock());
#endif

	return next;
}


/* _finish_switch - we just finished the switch away from prev
 */
static void gsnnpfpca_finish_switch(struct task_struct *prev)
{
	cpu_entry_t* 	entry = &__get_cpu_var(gsnnpfpca_cpu_entries);
	//int16_t cp_mask;
	//int cpu;
	int ret = 0;

	entry->scheduled = is_realtime(current) ? current : NULL;
	TRACE_TASK(current, "switched to\n");
    if (is_realtime(current))
    {
        if (tsk_rt(current)->job_params.cache_state & (CACHE_WILL_USE | CACHE_IN_USE))
        {
	        raw_spin_lock(&gsnnpfpca_cache_lock);
			ret = __lock_cache_ways_to_cpu(entry->cpu, tsk_rt(current)->job_params.cache_partitions);
			if (ret)
			{
				TRACE("[BUG][P%d] PL310 lock cache 0x%d fails\n",
					cpu, cp_mask);
			}
            selective_flush_cache_partitions(entry->cpu,
                tsk_rt(current)->job_params.cache_partitions, current, &gsnfpca);
	        raw_spin_unlock(&gsnnpfpca_cache_lock);
        }
        
        if (tsk_rt(current)->job_params.cache_state & (CACHE_WILL_CLEAR | CACHE_CLEARED))
        {
            int ret = 0;
	        raw_spin_lock(&gsnnpfpca_cache_lock);
            ret = __unlock_cache_ways_to_cpu(entry->cpu);
	        raw_spin_unlock(&gsnnpfpca_cache_lock);
            if (ret)
            {
                TRACE("[BUG][P%d] PL310 unlock cache 0x%d fails\n",
            		  cpu, cp_mask);
            }
        }
       
    }
//	if (is_realtime(current))
//	{
//		TRACE_TASK(current, "lock cache ways 0x%x\n", tsk_rt(current)->job_params.cache_partitions);
//		if (tsk_rt(current)->job_params.cache_state & (CACHE_WILL_USE | CACHE_IN_USE))
//		{
//			cp_mask = tsk_rt(current)->job_params.cache_partitions;
//			cpu = tsk_rt(current)->linked_on;
//			if (tsk_rt(current)->task_params.num_cache_partitions != 0 &&
//			    tsk_rt(current)->job_params.cache_partitions == 0)
//			{
//				TRACE_TASK(current, "[BUG] assigned cp=0x%x should not be 0\n",
//					tsk_rt(current)->job_params.cache_partitions);
//			}
//			lock_cache_partitions(cpu, cp_mask);
//		} else {
//			TRACE_TASK(current, "[BUG] cache_state=%d(%s) should be IN_USE\n",
//				tsk_rt(current)->job_params.cache_state,
//				cache_state_name(tsk_rt(current)->job_params.cache_state));
//		}
//	}
//	if (is_realtime(prev))
//	{
//		if (tsk_rt(prev)->job_params.cache_state & (CACHE_WILL_CLEAR | CACHE_CLEARED))
//		{
//			cp_mask = tsk_rt(prev)->job_params.cache_partitions;
//			cpu = tsk_rt(prev)->linked_on;
//			unlock_cache_partitions(cpu, cp_mask);	
//		} else {
//			TRACE_TASK(prev, "[BUG] cache_state=%d(%s) should be CLEAR\n",
//				tsk_rt(prev)->job_params.cache_state,
//				cache_state_name(tsk_rt(prev)->job_params.cache_state));
//		}
//	}

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "switched away from\n");
#endif
}


/*	Prepare a task for running in RT mode
 */
static void gsnnpfpca_task_new(struct task_struct * t, int on_rq, int is_scheduled)
{
	unsigned long 		flags;
	cpu_entry_t* 		entry;

	TRACE("gsn fpca: task new %d\n", t->pid);

	raw_spin_lock_irqsave(&gsnnpfpca_lock, flags);

	/* Init job param before check_for_preemption */
	TRACE_TASK(t, "cp_mask=0x%x before we set it to 0\n",
			   tsk_rt(t)->job_params.cache_partitions);
	tsk_rt(t)->job_params.cache_partitions = 0;
	set_cache_config(&gsnnpfpca, t, CACHE_INIT);

	/* setup job params */
	release_at(t, litmus_clock());

	if (is_scheduled) {
		entry = &per_cpu(gsnnpfpca_cpu_entries, task_cpu(t));
		BUG_ON(entry->scheduled);

#ifdef CONFIG_RELEASE_MASTER
		if (entry->cpu != gsnnpfpca.release_master) {
#endif
			entry->scheduled = t;
			tsk_rt(t)->scheduled_on = task_cpu(t);
#ifdef CONFIG_RELEASE_MASTER
		} else {
			/* do not schedule on release master */
			preempt(entry); /* force resched */
			tsk_rt(t)->scheduled_on = NO_CPU;
		}
#endif
	} else {
		t->rt_param.scheduled_on = NO_CPU;
	}
	t->rt_param.linked_on          = NO_CPU;

	if (is_running(t))
		gsnnpfpca_job_arrival(t);
	raw_spin_unlock_irqrestore(&gsnnpfpca_lock, flags);
}

static void gsnnpfpca_task_wake_up(struct task_struct *task)
{
	unsigned long flags;
	lt_t now;

	TRACE_TASK(task, "wake_up at %llu, cp_mask=0x%x\n",
			   litmus_clock(), tsk_rt(task)->job_params.cache_partitions);

	raw_spin_lock_irqsave(&gsnnpfpca_lock, flags);
	now = litmus_clock();
	if (is_sporadic(task) && is_tardy(task, now)) {
		/* new sporadic release */
		release_at(task, now);
		sched_trace_task_release(task);
	}
	gsnnpfpca_job_arrival(task);
	raw_spin_unlock_irqrestore(&gsnnpfpca_lock, flags);
}

static void gsnnpfpca_task_block(struct task_struct *t)
{
	rt_domain_t *rt = &gsnnpfpca;
	unsigned long flags;

	TRACE_TASK(t, "block at %llu, cp_mask=0x%x\n",
			   litmus_clock(), tsk_rt(t)->job_params.cache_partitions);

	/* unlink if necessary, Always clear cache before unlink */
	raw_spin_lock_irqsave(&gsnnpfpca_lock, flags);
	set_cache_config(rt, t, CACHE_WILL_CLEAR);
	unlink(t);
	TRACE_TASK(t, "blocked, rt.used_cp_mask=0x%x should not include job.cp_mask=0x%x\n",
			   rt->used_cache_partitions, tsk_rt(t)->job_params.cache_partitions);
	/* schedule point when task is blocked */
	check_for_preemptions();
	raw_spin_unlock_irqrestore(&gsnnpfpca_lock, flags);

	BUG_ON(!is_realtime(t));
}


static void gsnnpfpca_task_exit(struct task_struct * t)
{
	rt_domain_t *rt = &gsnnpfpca;
	unsigned long flags;

	/* unlink if necessary */
	raw_spin_lock_irqsave(&gsnnpfpca_lock, flags);
	/* Unlock cache before unlink task since
 	 * we need to know which CPU to unlock for */
	set_cache_config(rt, t, CACHE_WILL_CLEAR);
	set_cache_config(rt, t, CACHE_CLEARED);
	unlink(t);
	/* Do simple schedule here instead of gsnnpfpca_schedule() */
	if (tsk_rt(t)->scheduled_on != NO_CPU) {
		gsnnpfpca_cpus[tsk_rt(t)->scheduled_on]->scheduled = NULL;
		tsk_rt(t)->scheduled_on = NO_CPU;
	}
	TRACE_TASK(t, "exit, used_cp_mask=0x%x cleared by job.cp_mask=0x%x\n",
			   rt->used_cache_partitions, tsk_rt(t)->job_params.cache_partitions);
	/* schedule point when task is blocked */
	check_for_preemptions();
	raw_spin_unlock_irqrestore(&gsnnpfpca_lock, flags);

	BUG_ON(!is_realtime(t));
        TRACE_TASK(t, "RIP\n");
}

/*
 *	Deactivate current task until the beginning of the next period.
 *	cache_state is set to CACHE_WILL_CLEAR in caller
 */
long gsnnpfpca_complete_job(void)
{
	TRACE_TASK(current, "%s/%d/%d completed\n",
			   current->comm, current->pid, tsk_rt(current)->job_params.job_no);
	/* Mark that we do not excute anymore */
	tsk_rt(current)->completed = 1;
	/* call schedule, this will return when a new job arrives
	 * it also takes care of preparing for the next release
	 */
	schedule();
	return 0;
}

static long gsnnpfpca_admit_task(struct task_struct* tsk)
{
	if (litmus_is_valid_fixed_prio(get_priority(tsk)))
	{
		INIT_LIST_HEAD(&tsk_rt(tsk)->standby_list);
    	TRACE_TASK(tsk, "is admitted, num_cp=%d, job.cp_mask=0x%x (should be 0x0)\n",
				   tsk_rt(tsk)->task_params.num_cache_partitions,
				   tsk_rt(tsk)->job_params.cache_partitions);
		return 0;
	} else {
        TRACE_TASK(tsk, "is rejected\n");
        return -EINVAL;
	}
}

/* NOTE: GSN-NPFPCA does not consider LITMUS_LOCKING protocol now! 
 * The code under CONFIG_LITMUS_LOCKING should never be used! */

static struct domain_proc_info gsnnpfpca_domain_proc_info;
static long gsnnpfpca_get_domain_proc_info(struct domain_proc_info **ret)
{
	*ret = &gsnnpfpca_domain_proc_info;
	return 0;
}

static void gsnnpfpca_setup_domain_proc(void)
{
	int i, cpu;
	int release_master =
#ifdef CONFIG_RELEASE_MASTER
			atomic_read(&release_master_cpu);
#else
		NO_CPU;
#endif
	int num_rt_cpus = num_online_cpus() - (release_master != NO_CPU);
	struct cd_mapping *map;

	memset(&gsnnpfpca_domain_proc_info, sizeof(gsnnpfpca_domain_proc_info), 0);
	init_domain_proc_info(&gsnnpfpca_domain_proc_info, num_rt_cpus, 1);
	gsnnpfpca_domain_proc_info.num_cpus = num_rt_cpus;
	gsnnpfpca_domain_proc_info.num_domains = 1;

	gsnnpfpca_domain_proc_info.domain_to_cpus[0].id = 0;
	for (cpu = 0, i = 0; cpu < num_online_cpus(); ++cpu) {
		if (cpu == release_master)
			continue;
		map = &gsnnpfpca_domain_proc_info.cpu_to_domains[i];
		map->id = cpu;
		cpumask_set_cpu(0, map->mask);
		++i;

		/* add cpu to the domain */
		cpumask_set_cpu(cpu,
			gsnnpfpca_domain_proc_info.domain_to_cpus[0].mask);
	}
}

static long gsnnpfpca_activate_plugin(void)
{
	int cpu;
	cpu_entry_t *entry;

	bheap_init(&gsnnpfpca_cpu_heap);
#ifdef CONFIG_RELEASE_MASTER
	gsnnpfpca.release_master = atomic_read(&release_master_cpu);
#endif

	for_each_online_cpu(cpu) {
		entry = &per_cpu(gsnnpfpca_cpu_entries, cpu);
		bheap_node_init(&entry->hn, entry);
		entry->linked    = NULL;
		entry->scheduled = NULL;
#ifdef CONFIG_RELEASE_MASTER
		if (cpu != gsnnpfpca.release_master) {
#endif
			TRACE("GSN-NPFPCA: Initializing CPU #%d.\n", cpu);
			update_cpu_position(entry);
#ifdef CONFIG_RELEASE_MASTER
		} else {
			TRACE("GSN-NPFPCA: CPU %d is release master.\n", cpu);
		}
#endif
	}

	gsnnpfpca_setup_domain_proc();
	gsnnpfpca.used_cache_partitions = 0;
	TRACE("gsnnpfpca_activate_plugin used_cp_mask=0x%x\n",
		  gsnnpfpca.used_cache_partitions);

	return 0;
}

static long gsnnpfpca_deactivate_plugin(void)
{
	destroy_domain_proc_info(&gsnnpfpca_domain_proc_info);
	return 0;
}

/*	Plugin object	*/
static struct sched_plugin gsn_npfpca_plugin __cacheline_aligned_in_smp = {
	.plugin_name		= "GSN-NPFPCA",
	.finish_switch		= gsnnpfpca_finish_switch,
	.task_new		= gsnnpfpca_task_new,
	.complete_job		= gsnnpfpca_complete_job,
	.task_exit		= gsnnpfpca_task_exit,
	.schedule		= gsnnpfpca_schedule,
	.task_wake_up		= gsnnpfpca_task_wake_up,
	.task_block		= gsnnpfpca_task_block,
	.admit_task		= gsnnpfpca_admit_task,
	.activate_plugin	= gsnnpfpca_activate_plugin,
	.deactivate_plugin	= gsnnpfpca_deactivate_plugin,
	.get_domain_proc_info	= gsnnpfpca_get_domain_proc_info,
#ifdef CONFIG_LITMUS_LOCKING
	.allocate_lock		= gsnnpfpca_allocate_lock,
#endif
};


static int __init init_gsn_npfpca(void)
{
	int cpu;
	cpu_entry_t *entry;
	cpu_cache_entry_t *cache_entry;

	INIT_LIST_HEAD(&tsk_rt(&standby_tasks)->standby_list);
	memset(&standby_cpus, 0, sizeof(standby_cpus));

	bheap_init(&gsnnpfpca_cpu_heap);
	/* initialize CPU state */
	for (cpu = 0; cpu < NR_CPUS; cpu++)  {
		entry = &per_cpu(gsnnpfpca_cpu_entries, cpu);
		gsnnpfpca_cpus[cpu] = entry;
		entry->cpu 	 = cpu;
		entry->hn        = &gsnnpfpca_heap_node[cpu];
		bheap_node_init(&entry->hn, entry);
		cache_entry = &per_cpu(cpu_cache_entries, cpu);
		TRACE("[P%d] gsn_npfpca: cpu:%d->%d used_cpu:%d->0\n",
			  cpu, cache_entry->cpu, cpu, cache_entry->used_cp);
		cache_entry->cpu = cpu;
		cache_entry->used_cp = 0;
		/* init cache controller, not use any cache 
 		 * no need to grab lock now since only init once */
		if(__lock_cache_ways_to_cpu(cpu, 0x0))
		{
			TRACE("P%d lock cache ways 0x0 fails\n", cpu);
			printk("P%d lock cache ways 0x0 fails\n", cpu);
		}
	}
	/* write back all cache */
	flush_cache_ways(0xffff);
	fp_domain_init(&gsnnpfpca, NULL, gsnnpfpca_release_jobs);
	gsnnpfpca.used_cache_partitions = 0;
	TRACE("init_gsn_npfpca: rt.used_cp_mask=0x%x\n", gsnnpfpca.used_cache_partitions);
	return register_sched_plugin(&gsn_npfpca_plugin);
}


module_init(init_gsn_npfpca);
