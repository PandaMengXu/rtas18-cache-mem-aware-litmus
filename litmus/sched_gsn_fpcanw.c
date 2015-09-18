/*
 * litmus/sched_gsn_fpcanw.c
 *
 * Implementation of the GSN-FPCANW scheduling algorithm.
 * Copy from litmus/sched_gsn_fpca.c
 *
 * GSN-FPCANW is the gFPca^nw algorithm desribed in the paper.
 * It does not allow priority inversion.
 * When a high priority ready task is blocked by cache, all other
 * ready tasks in ready_queue will not be allowed to execute.
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

/* Overview of GSN-FPCANW operations.
 *
 * For a detailed explanation of GSN-FPCANW have a look at the FMLP paper. This
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
 *                                currently queued in the gsnfpcanw queue it will
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
 * gsnfpcanw_job_arrival(T)	- This is the catch all function when T enters
 *                                the system after either a suspension or at a
 *                                job release. It will queue T (which means it
 *                                is not safe to call gsnfpcanw_job_arrival(T) if
 *                                T is already queued) and then check whether a
 *                                preemption is necessary. If a preemption is
 *                                necessary it will update the linkage
 *                                accordingly and cause scheduled to be called
 *                                (either with an IPI or need_resched). It is
 *                                safe to call gsnfpcanw_job_arrival(T) if T's
 *                                next job has not been actually released yet
 *                                (releast time in the future). T will be put
 *                                on the release queue in that case.
 *
 * job_completion(T)		- Take care of everything that needs to be done
 *                                to prepare T for its next release and place
 *                                it in the right queue with
 *                                gsnfpcanw_job_arrival().
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
DEFINE_PER_CPU(cpu_entry_t, gsnfpcanw_cpu_entries);

cpu_entry_t* gsnfpcanw_cpus[NR_CPUS];

/* the cpus queue themselves according to priority in here */
static struct bheap_node gsnfpcanw_heap_node[NR_CPUS];
static struct bheap      gsnfpcanw_cpu_heap;

rt_domain_t gsnfpcanw;
#define gsnfpcanw_lock (gsnfpcanw.ready_lock)

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
 *                       order in the cpu queue. Caller must hold gsnfpcanw lock.
 */
static void update_cpu_position(cpu_entry_t *entry)
{
	if (likely(bheap_node_in_heap(entry->hn)))
		bheap_delete(cpu_lower_prio, &gsnfpcanw_cpu_heap, entry->hn);
	bheap_insert(cpu_lower_prio, &gsnfpcanw_cpu_heap, entry->hn);
}

/* caller must hold gsnfpcanw lock */
static cpu_entry_t* lowest_prio_cpu(void)
{
	struct bheap_node* hn;
	hn = bheap_peek(cpu_lower_prio, &gsnfpcanw_cpu_heap);
	return hn->value;
}

static void remove_cpu(cpu_entry_t *entry)
{
	if (likely(bheap_node_in_heap(entry->hn)))
		bheap_delete(cpu_lower_prio, &gsnfpcanw_cpu_heap, entry->hn);
}

static void insert_cpu(cpu_entry_t *entry)
{
	bheap_insert(cpu_lower_prio, &gsnfpcanw_cpu_heap, entry->hn);
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
			sched = &per_cpu(gsnfpcanw_cpu_entries, on_cpu);
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
 *          where it was linked before. Must hold gsnfpcanw_lock.
 */
static noinline void unlink(struct task_struct* t)
{
	cpu_entry_t *entry;

	if (t->rt_param.linked_on != NO_CPU) {
		/* unlink */
		entry = &per_cpu(gsnfpcanw_cpu_entries, t->rt_param.linked_on);
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
		remove(&gsnfpcanw, t);
	}
}


/* preempt - force a CPU to reschedule
 */
static void preempt(cpu_entry_t *entry)
{
	preempt_if_preemptable(entry->scheduled, entry->cpu);
}

/* requeue - Put an unlinked task into gsn-fpcanw domain.
 *           Caller must hold gsnfpcanw_lock.
 */
static noinline void requeue(struct task_struct* task)
{
	BUG_ON(!task);
	/* sanity check before insertion */
	BUG_ON(is_queued(task));

	if (is_early_releasing(task) || is_released(task, litmus_clock()))
		__add_ready(&gsnfpcanw, task);
	else {
		/* it has got to wait */
		add_release(&gsnfpcanw, task);
	}
}

#ifdef CONFIG_SCHED_CPU_AFFINITY
static cpu_entry_t* gsnfpcanw_get_nearest_available_cpu(cpu_entry_t *start)
{
	cpu_entry_t *affinity;

	get_nearest_available_cpu(affinity, start, gsnfpcanw_cpu_entries,
#ifdef CONFIG_RELEASE_MASTER
			gsnfpcanw.release_master
#else
			NO_CPU
#endif
			);

	return(affinity);
}
#endif

/* check for any necessary preemptions under gFPca^nw */
static void check_for_preemptions(void)
{
	rt_domain_t *rt = &gsnfpcanw;
	struct task_struct *task;
	int num_used_cache_partitions = 0;
	int cpu_ok = 0;
	int cache_ok = 0;
	int only_take_idle_cache = 0;
	uint16_t cp_mask_to_use = 0; /* mask of cache partitions the task to use */
	int num_cp_to_use = 0;
	struct task_struct preempted_tasks;
	cpu_entry_t *cpu_to_preempt = NULL;
	int i;
	struct list_head *iter, *tmp;

	INIT_LIST_HEAD(&tsk_rt(&preempted_tasks)->standby_list);

	/*TODO: Assume no priority inversion first! */
	task = __peek_ready(&gsnfpcanw);

	if (!task) {
		TRACE_TASK(task, "No ready RT tasks\n");
		goto out;
	}

	TRACE_TASK(task, "check_for_preemptions...\n");

	/* Check if local cpu is idle first */
	cpu_to_preempt = &__get_cpu_var(gsnfpcanw_cpu_entries);
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
		only_take_idle_cache = 1;
		cp_mask_to_use = 0;
		for(i=0; i<MAX_NUM_CACHE_PARTITIONS; i++)
		{
			if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
				break;
			if (!(rt->used_cache_partitions & (1<<i) & CACHE_PARTITIONS_MASK))
			{
				if (cp_mask_to_use & (1<<i) & CACHE_PARTITIONS_MASK)
					TRACE_TASK(task, "cp_mask_to_use=0x%x double set i=%d\n",
							   cp_mask_to_use, i);
				cp_mask_to_use |= (1<<i) & CACHE_PARTITIONS_MASK;
				num_cp_to_use += 1;
			}
		}
		/* Find the lowest priority CPU to preempt
 		 * We should use linked here since a preempting task may be linked
 		 * but have not be executed on the CPU */
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
	} else
	{
		int cpu = 0;

		BUG_ON(num_cp_to_use);
		/* take idle cache partitions first */
		for(i=0; i<MAX_NUM_CACHE_PARTITIONS; i++)
		{
			if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
			{
				TRACE_TASK(task, "[BUG] Idle cache is enough but still try to preempt cache\n");
				break;
			}
			if (!(rt->used_cache_partitions & (1<<i) & CACHE_PARTITIONS_MASK))
			{
				if (cp_mask_to_use & (1<<i) & CACHE_PARTITIONS_MASK)
					TRACE_TASK(task, "cp_mask_to_use=0x%x double set i=%d\n",
							   cp_mask_to_use, i);
				cp_mask_to_use |= (1<<i) & CACHE_PARTITIONS_MASK;
				num_cp_to_use++;
			}
		}
		TRACE_TASK(task, "take idle cps 0x%x\n", cp_mask_to_use);

		//BUG_ON(num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions);
		if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
		{
			TRACE_TASK(task, "[BUG] num_cp_to_use=%d >= task.num_cp=%d\n",
					   num_cp_to_use, tsk_rt(task)->task_params.num_cache_partitions);
		}
		do { /* Iterate all CPUs in increasing order */
			cpu_entry_t* entry = lowest_prio_cpu();
			struct task_struct* cur;

			if (!entry)
				break;
			cur = entry->linked;
			standby_cpus[entry->cpu] = entry;
			remove_cpu(entry);
			if (!cur || !is_realtime(cur))
			{
				if (!cpu_ok)
				{
					cpu_ok = 1;
					cpu_to_preempt = entry;
				}
				cpu++;
				continue;
			}
			/* RT task may have not locked any cache partition */
			if (!(tsk_rt(cur)->job_params.cache_state & (CACHE_WILL_USE | CACHE_IN_USE)))
			{
				cpu++;
				TRACE_TASK(cur, "[BUG] was linked but is not in CACHE_WILL_USE or CACHE_IN_USE\n");
				continue;
			}
			if (!fp_higher_prio(task, cur))
				break;
			if (!cpu_ok)
			{
				cpu_ok = 1;
				cpu_to_preempt = entry;
			}
			list_add(&tsk_rt(cur)->standby_list, &tsk_rt(&preempted_tasks)->standby_list);
			if(count_set_bits(tsk_rt(cur)->job_params.cache_partitions) 
				   != tsk_rt(cur)->task_params.num_cache_partitions)
			{
				printk("[BUG] task=%d, job=%d, job.cp_mask=0x%x, count_set_bits=%d, task.num_cp=%d, rt.used_cp_mask=0x%x\n",
						   cur->pid,
						   tsk_rt(cur)->job_params.job_no,
						   tsk_rt(cur)->job_params.cache_partitions,
						   count_set_bits(tsk_rt(cur)->job_params.cache_partitions),
						   tsk_rt(cur)->task_params.num_cache_partitions,
						   rt->used_cache_partitions);
				TRACE_TASK(cur, "[BUG] job=%d, job.cp_mask=0x%x, count_set_bits=%d, task.num_cp=%d, rt.used_cp_mask=0x%x\n",
						   tsk_rt(cur)->job_params.job_no,
						   tsk_rt(cur)->job_params.cache_partitions,
						   count_set_bits(tsk_rt(cur)->job_params.cache_partitions),
						   tsk_rt(cur)->task_params.num_cache_partitions,
						   rt->used_cache_partitions);
			}
			num_cp_to_use += tsk_rt(cur)->task_params.num_cache_partitions;
			if (num_cp_to_use <= tsk_rt(task)->task_params.num_cache_partitions) {
				if (cp_mask_to_use & tsk_rt(cur)->job_params.cache_partitions)
				{
					TRACE_TASK(task, "[BUG] preempt %s/%d/%d cache 0x%x but already has cache 0x%x\n",
				   			   cur->comm, cur->pid, tsk_rt(cur)->job_params.job_no,
							   tsk_rt(cur)->job_params.cache_partitions,
							   cp_mask_to_use);
				}
				cp_mask_to_use |= tsk_rt(cur)->job_params.cache_partitions;
			} else {
				num_cp_to_use -= tsk_rt(cur)->task_params.num_cache_partitions;
				for(i=0; i<MAX_NUM_CACHE_PARTITIONS; i++)
				{
					if (tsk_rt(cur)->job_params.cache_partitions & (1<<i))
					{
						if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
							break;
						if (cp_mask_to_use & (1<<i))
						{
							TRACE_TASK(task, "[BUG] preempt %s/%d/%d cache 0x%x (i=%d) but already has cache 0x%x\n",
									   cur->comm, cur->pid, tsk_rt(cur)->job_params.job_no,
									   tsk_rt(cur)->job_params.cache_partitions, i,
									   cp_mask_to_use);
						}
						num_cp_to_use++;
						cp_mask_to_use |= (1<<i);
					}
				}
			}
			TRACE_TASK(task, "preempt %s/%d/%d, cp_mask_to_use=0x%x\n",
					   cur->comm, cur->pid, tsk_rt(cur)->job_params.job_no, cp_mask_to_use);
			/* Stop searching preempted cache when we find enough */
			if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
				break;
			cpu++;
		} while (cpu < NR_CPUS);
		if (num_cp_to_use >= tsk_rt(task)->task_params.num_cache_partitions)
			cache_ok = 1;
		else { /* clear preempted list if not preempt */
			struct list_head *iter, *tmp;
			cache_ok = 0;
			list_for_each_safe(iter, tmp, &tsk_rt(&preempted_tasks)->standby_list) {
				list_del_init(iter);
			}
		}
		/* restore the cpu bheap */
		for (cpu = 0; cpu < NR_CPUS; cpu++)  {
			if (standby_cpus[cpu] != NULL)
				insert_cpu(standby_cpus[cpu]);
		}
		memset(&standby_cpus, 0, sizeof(standby_cpus));
	} /* Have picked cache partitions */

	/* If preemptible, link task to preempted cpu, preempt preempted_tasks*/
	if ( !cache_ok || !cpu_ok )
	{
		TRACE_TASK(task, "Cannot preempt, cache_ok=%d, cpu_ok=%d, rt.used_cp_mask=0x%x, need %d cps\n",
				   cache_ok, cpu_ok, rt->used_cache_partitions, tsk_rt(task)->task_params.num_cache_partitions);
		goto out;
	}
	/* Preempt preempted tasks */
	BUG_ON(!cpu_to_preempt);
	/* Must take_ready before we requeue any task */
	task = __take_ready(&gsnfpcanw);
	BUG_ON(!task);
	if (!only_take_idle_cache)
	{
		list_for_each_safe(iter, tmp, &tsk_rt(&preempted_tasks)->standby_list) {
			struct rt_param *rt_cur = list_entry(iter, struct rt_param, standby_list);
			struct task_struct *tsk_cur = list_entry(rt_cur, struct task_struct, rt_param); /* correct */
			cpu_entry_t *cpu_entry = gsnfpcanw_cpus[rt_cur->linked_on];
			list_del_init(&rt_cur->standby_list);
			if (cpu_entry->cpu != cpu_to_preempt->cpu)
			{
				/* requeue the linked task; scheduled task is requeued at schedule() */
				if (requeue_preempted_job(cpu_entry->linked))
					requeue(cpu_entry->linked);
				/* update global view of cache partitions */
				set_cache_config(rt, tsk_cur, CACHE_WILL_CLEAR);
				link_task_to_cpu(NULL, cpu_entry);
				cpu_entry->preempting = task;
				preempt(cpu_entry);
			}
		}
		INIT_LIST_HEAD(&tsk_rt(&standby_tasks)->standby_list);
	}
	/* Link task and preempt the cpu_to_preempt */
	/* The preempted CPU may be preempted by cache or CPU only
 	 * Must be executed in both situation
 	 * Otherwise will fail to link the task and the task will never be sched
 	 * NOTE: We must requeue the preempted task on preempted CPU, otherwise,
 	 * scheduler will lose track of the preempted task.
 	 * Unless task volunteerly yield CPU by finishing its job,
 	 * preempting CPU has the responsibility to add preempted task back to
 	 * ready_queue since preempted task must be runnable 
 	 * BUG FIX: A RT task may be preempted only by CPU when system has enough
 	 * free cache! Preempting task take free cache, release cache of 
 	 * preempted task AND requeue the preempted task */
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
	return;
}

/* gsnfpcanw_job_arrival: task is either resumed or released
 * We do not need to clear cache first at job arrival
 * Job arrival occurs only when previous job completion occurs,
 * which has set cache state to CACHE_WILL_CLEAR already
 */
static noinline void gsnfpcanw_job_arrival(struct task_struct* task)
{
	BUG_ON(!task);

	TRACE_TASK(task, "gsnfpcanw_job_arrival %s/%d/%d\n",
			   task->comm, task->pid,
			   tsk_rt(task)->job_params.job_no);
	requeue(task);
	check_for_preemptions();
}

static void gsnfpcanw_release_jobs(rt_domain_t* rt, struct bheap* tasks)
{
	unsigned long flags;

	TRACE("gsnfpcanw_release_jobs\n");
	raw_spin_lock_irqsave(&gsnfpcanw_lock, flags);

	__merge_ready(rt, tasks);
	check_for_preemptions();

	raw_spin_unlock_irqrestore(&gsnfpcanw_lock, flags);
}

/* caller holds gsnfpcanw_lock */
static noinline void job_completion(struct task_struct *t, int forced)
{
	rt_domain_t *rt = &gsnfpcanw;
	BUG_ON(!t);

	sched_trace_task_completion(t, forced);

	TRACE_TASK(t, "job_completion(). release cp_mask=0x%x, current used_cp_mask=0x%x\n",
			   tsk_rt(t)->job_params.cache_partitions, rt->used_cache_partitions);

	/* set flags */
	tsk_rt(t)->completed = 0;
	set_cache_config(rt, t, CACHE_WILL_CLEAR);
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
		gsnfpcanw_job_arrival(t);
}

void gsnfpcanw_dump_cpus()
{
	int i;
	cpu_entry_t *entry = NULL;
	struct task_struct *ltask, *stask;

	for (i = 0; i < NR_CPUS; i++)
	{
		entry = gsnfpcanw_cpus[i];
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

/* gsnfpcanw_check_sched_invariant
 * Check sched invariant at end of gsnfpcanw_schedule
 * gsnfpcanw.lock is grabbed by caller
 * Invariant: At the end of schedule() on a CPU,
 * the current linked task on the CPU should NOT be preemptable
 * by the top task in ready_queue
 */
void gsnfpcanw_check_sched_invariant()
{
	int i;
	cpu_entry_t *entry = NULL;
	struct task_struct *task = NULL;
	struct task_struct *qtask = NULL;
	struct task_struct *preempted_task = NULL;
	rt_domain_t *rt = &gsnfpcanw;
	int num_used_cp = 0;
	int num_avail_cp = 0;
	int cpu_ok = 0;
	int preempted_cpu = -1;

	qtask = __peek_ready(&gsnfpcanw);
	/* No ready RT task */
	if (!qtask)
		return;

	/* Top ready task has higher priority? */
	entry = &__get_cpu_var(gsnfpcanw_cpu_entries);
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
		entry = gsnfpcanw_cpus[i];
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
		gsnfpcanw_dump_cpus();
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
static struct task_struct* gsnfpcanw_schedule(struct task_struct * prev)
{
	rt_domain_t *rt = &gsnfpcanw;
	cpu_entry_t* entry = &__get_cpu_var(gsnfpcanw_cpu_entries);
	int out_of_time, sleep, preempt, np, exists, blocks, finish;
	struct task_struct* next = NULL;
	cache_state_t cache_state_prev;

#ifdef CONFIG_RELEASE_MASTER
	/* Bail out early if we are the release master.
	 * The release master never schedules any real-time tasks.
	 */
	if (unlikely(gsnfpcanw.release_master == entry->cpu)) {
		sched_state_task_picked();
		return NULL;
	}
#endif

	raw_spin_lock(&gsnfpcanw_lock);

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

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "invoked gsnfpcanw_schedule.\n");
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
	if (!np && (out_of_time || sleep) && !blocks)
	{
		finish = 1;
		job_completion(entry->scheduled, !sleep);
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
			set_cache_config(rt, entry->scheduled, CACHE_WILL_CLEAR);
			/* not gonna be scheduled soon */
			entry->scheduled->rt_param.scheduled_on = NO_CPU;
			/* No need to set job_params.cache_partitions to 0 because cache_state has indicated that. */
			TRACE_TASK(entry->scheduled, "scheduled_on = NO_CPU, rt->used_cp_mask=0x%x should exclude job.cp_mask=0x%x\n",
					   rt->used_cache_partitions, entry->scheduled->rt_param.job_params.cache_partitions);
			/* Trace when preempted via cache by another CPU */
			if (!entry->linked && !finish)
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
	gsnfpcanw_check_sched_invariant();

	raw_spin_unlock(&gsnfpcanw_lock);

#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(next, "gsnfpcanw_lock released\n");

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
static void gsnfpcanw_finish_switch(struct task_struct *prev)
{
	cpu_entry_t* 	entry = &__get_cpu_var(gsnfpcanw_cpu_entries);

	entry->scheduled = is_realtime(current) ? current : NULL;
	if (is_realtime(current))
		TRACE_TASK(current, "lock cache ways 0x%x\n", tsk_rt(current)->job_params.cache_partitions);
#ifdef WANT_ALL_SCHED_EVENTS
	TRACE_TASK(prev, "switched away from\n");
#endif
}


/*	Prepare a task for running in RT mode
 */
static void gsnfpcanw_task_new(struct task_struct * t, int on_rq, int is_scheduled)
{
	unsigned long 		flags;
	cpu_entry_t* 		entry;

	TRACE("gsn fpca: task new %d\n", t->pid);

	raw_spin_lock_irqsave(&gsnfpcanw_lock, flags);

	/* Init job param before check_for_preemption */
	TRACE_TASK(t, "cp_mask=0x%x before we set it to 0\n",
			   tsk_rt(t)->job_params.cache_partitions);
	tsk_rt(t)->job_params.cache_partitions = 0;
	set_cache_config(&gsnfpcanw, t, CACHE_INIT);

	/* setup job params */
	release_at(t, litmus_clock());

	if (is_scheduled) {
		entry = &per_cpu(gsnfpcanw_cpu_entries, task_cpu(t));
		BUG_ON(entry->scheduled);

#ifdef CONFIG_RELEASE_MASTER
		if (entry->cpu != gsnfpcanw.release_master) {
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
		gsnfpcanw_job_arrival(t);
	raw_spin_unlock_irqrestore(&gsnfpcanw_lock, flags);
}

static void gsnfpcanw_task_wake_up(struct task_struct *task)
{
	unsigned long flags;
	lt_t now;

	TRACE_TASK(task, "wake_up at %llu, cp_mask=0x%x\n",
			   litmus_clock(), tsk_rt(task)->job_params.cache_partitions);

	raw_spin_lock_irqsave(&gsnfpcanw_lock, flags);
	now = litmus_clock();
	if (is_sporadic(task) && is_tardy(task, now)) {
		/* new sporadic release */
		release_at(task, now);
		sched_trace_task_release(task);
	}
	gsnfpcanw_job_arrival(task);
	raw_spin_unlock_irqrestore(&gsnfpcanw_lock, flags);
}

static void gsnfpcanw_task_block(struct task_struct *t)
{
	rt_domain_t *rt = &gsnfpcanw;
	unsigned long flags;

	TRACE_TASK(t, "block at %llu, cp_mask=0x%x\n",
			   litmus_clock(), tsk_rt(t)->job_params.cache_partitions);

	/* unlink if necessary */
	raw_spin_lock_irqsave(&gsnfpcanw_lock, flags);
	set_cache_config(rt, t, CACHE_WILL_CLEAR);
	unlink(t);
	TRACE_TASK(t, "blocked, rt.used_cp_mask=0x%x should not include job.cp_mask=0x%x\n",
			   rt->used_cache_partitions, tsk_rt(t)->job_params.cache_partitions);
	raw_spin_unlock_irqrestore(&gsnfpcanw_lock, flags);

	BUG_ON(!is_realtime(t));
}


static void gsnfpcanw_task_exit(struct task_struct * t)
{
	rt_domain_t *rt = &gsnfpcanw;
	unsigned long flags;

	/* unlink if necessary */
	raw_spin_lock_irqsave(&gsnfpcanw_lock, flags);
	/* Unlock cache before unlink task since
 	 * we need to know which CPU to unlock for */
	set_cache_config(rt, t, CACHE_WILL_CLEAR);
	set_cache_config(rt, t, CACHE_CLEARED);
	unlink(t);
	/* Do simple schedule here instead of gsnfpcanw_schedule() */
	if (tsk_rt(t)->scheduled_on != NO_CPU) {
		gsnfpcanw_cpus[tsk_rt(t)->scheduled_on]->scheduled = NULL;
		tsk_rt(t)->scheduled_on = NO_CPU;
	}
	TRACE_TASK(t, "exit, used_cp_mask=0x%x cleared by job.cp_mask=0x%x\n",
			   rt->used_cache_partitions, tsk_rt(t)->job_params.cache_partitions);
	raw_spin_unlock_irqrestore(&gsnfpcanw_lock, flags);

	BUG_ON(!is_realtime(t));
        TRACE_TASK(t, "RIP\n");
}

/*
 *	Deactivate current task until the beginning of the next period.
 *	cache_state is set to CACHE_WILL_CLEAR in caller
 */
long gsnfpcanw_complete_job(void)
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

static long gsnfpcanw_admit_task(struct task_struct* tsk)
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

/* NOTE: GSN-FPCANW does not consider LITMUS_LOCKING protocol now!
 * We removed anything related to CONFIG_LITMUS_LOCKING */

static struct domain_proc_info gsnfpcanw_domain_proc_info;
static long gsnfpcanw_get_domain_proc_info(struct domain_proc_info **ret)
{
	*ret = &gsnfpcanw_domain_proc_info;
	return 0;
}

static void gsnfpcanw_setup_domain_proc(void)
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

	memset(&gsnfpcanw_domain_proc_info, sizeof(gsnfpcanw_domain_proc_info), 0);
	init_domain_proc_info(&gsnfpcanw_domain_proc_info, num_rt_cpus, 1);
	gsnfpcanw_domain_proc_info.num_cpus = num_rt_cpus;
	gsnfpcanw_domain_proc_info.num_domains = 1;

	gsnfpcanw_domain_proc_info.domain_to_cpus[0].id = 0;
	for (cpu = 0, i = 0; cpu < num_online_cpus(); ++cpu) {
		if (cpu == release_master)
			continue;
		map = &gsnfpcanw_domain_proc_info.cpu_to_domains[i];
		map->id = cpu;
		cpumask_set_cpu(0, map->mask);
		++i;

		/* add cpu to the domain */
		cpumask_set_cpu(cpu,
			gsnfpcanw_domain_proc_info.domain_to_cpus[0].mask);
	}
}

static long gsnfpcanw_activate_plugin(void)
{
	int cpu;
	cpu_entry_t *entry;

	bheap_init(&gsnfpcanw_cpu_heap);
#ifdef CONFIG_RELEASE_MASTER
	gsnfpcanw.release_master = atomic_read(&release_master_cpu);
#endif

	for_each_online_cpu(cpu) {
		entry = &per_cpu(gsnfpcanw_cpu_entries, cpu);
		bheap_node_init(&entry->hn, entry);
		entry->linked    = NULL;
		entry->scheduled = NULL;
#ifdef CONFIG_RELEASE_MASTER
		if (cpu != gsnfpcanw.release_master) {
#endif
			TRACE("GSN-FPCANW: Initializing CPU #%d.\n", cpu);
			update_cpu_position(entry);
#ifdef CONFIG_RELEASE_MASTER
		} else {
			TRACE("GSN-FPCANW: CPU %d is release master.\n", cpu);
		}
#endif
	}

	gsnfpcanw_setup_domain_proc();
	gsnfpcanw.used_cache_partitions = 0;
	TRACE("gsnfpcanw_activate_plugin used_cp_mask=0x%x\n",
		  gsnfpcanw.used_cache_partitions);

	return 0;
}

static long gsnfpcanw_deactivate_plugin(void)
{
	destroy_domain_proc_info(&gsnfpcanw_domain_proc_info);
	return 0;
}

/*	Plugin object	*/
static struct sched_plugin gsn_fpca_plugin __cacheline_aligned_in_smp = {
	.plugin_name		= "GSN-FPCANW",
	.finish_switch		= gsnfpcanw_finish_switch,
	.task_new		= gsnfpcanw_task_new,
	.complete_job		= gsnfpcanw_complete_job,
	.task_exit		= gsnfpcanw_task_exit,
	.schedule		= gsnfpcanw_schedule,
	.task_wake_up		= gsnfpcanw_task_wake_up,
	.task_block		= gsnfpcanw_task_block,
	.admit_task		= gsnfpcanw_admit_task,
	.activate_plugin	= gsnfpcanw_activate_plugin,
	.deactivate_plugin	= gsnfpcanw_deactivate_plugin,
	.get_domain_proc_info	= gsnfpcanw_get_domain_proc_info,
#ifdef CONFIG_LITMUS_LOCKING
	.allocate_lock		= gsnfpcanw_allocate_lock,
#endif
};


static int __init init_gsn_fpcanw(void)
{
	int cpu;
	cpu_entry_t *entry;

	INIT_LIST_HEAD(&tsk_rt(&standby_tasks)->standby_list);
	memset(&standby_cpus, 0, sizeof(standby_cpus));

	bheap_init(&gsnfpcanw_cpu_heap);
	/* initialize CPU state */
	for (cpu = 0; cpu < NR_CPUS; cpu++)  {
		entry = &per_cpu(gsnfpcanw_cpu_entries, cpu);
		gsnfpcanw_cpus[cpu] = entry;
		entry->cpu 	 = cpu;
		entry->hn        = &gsnfpcanw_heap_node[cpu];
		bheap_node_init(&entry->hn, entry);
	}
	fp_domain_init(&gsnfpcanw, NULL, gsnfpcanw_release_jobs);
	gsnfpcanw.used_cache_partitions = 0;
	TRACE("init_gsn_fpcanw: rt.used_cp_mask=0x%x\n", gsnfpcanw.used_cache_partitions);
	return register_sched_plugin(&gsn_fpca_plugin);
}


module_init(init_gsn_fpcanw);
