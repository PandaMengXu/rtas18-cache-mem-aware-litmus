#
# Makefile for LITMUS^RT
#

obj-y     = sched_plugin.o litmus.o \
	    preempt.o \
	    litmus_proc.o \
	    budget.o \
	    clustered.o \
	    jobs.o \
	    sync.o \
	    rt_domain.o \
	    edf_common.o \
	    fp_common.o \
	    fdso.o \
	    locking.o \
	    srp.o \
	    bheap.o \
	    binheap.o \
	    ctrldev.o \
	    uncachedev.o \
		rt_cache.o \
	    sched_gsn_edf.o \
	    sched_psn_edf.o \
	    sched_gsn_fp.o \
	    sched_gsn_npfp.o \
	    sched_gsn_fpca.o \
	    sched_gsn_npfpca.o \
	    sched_gsn_fpcanw.o \
	    sched_pfp.o

obj-$(CONFIG_PLUGIN_CEDF) += sched_cedf.o
obj-$(CONFIG_PLUGIN_PFAIR) += sched_pfair.o

obj-$(CONFIG_SCHED_CPU_AFFINITY) += affinity.o

obj-$(CONFIG_FEATHER_TRACE) += ft_event.o ftdev.o
obj-$(CONFIG_SCHED_TASK_TRACE) += sched_task_trace.o
obj-$(CONFIG_SCHED_DEBUG_TRACE) += sched_trace.o
obj-$(CONFIG_SCHED_OVERHEAD_TRACE) += trace.o

# cache controller
obj-y    += cache_proc.o

