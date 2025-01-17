/*
 * included from arch/x86/include/asm/unistd_32.h
 *
 * LITMUS^RT syscalls with "relative" numbers
 * NOTE: Must add sys_ calls in arch/arm/kernel/calls.S
 */
#define __LSC(x) (__NR_LITMUS + x)

#define __NR_set_rt_task_param	__LSC(0)
#define __NR_get_rt_task_param	__LSC(1)
#define __NR_complete_job	__LSC(2)
#define __NR_od_open		__LSC(3)
#define __NR_od_close		__LSC(4)
#define __NR_litmus_lock       	__LSC(5)
#define __NR_litmus_unlock	__LSC(6)
#define __NR_query_job_no	__LSC(7)
#define __NR_wait_for_job_release __LSC(8)
#define __NR_wait_for_ts_release __LSC(9)
#define __NR_release_ts		__LSC(10)
#define __NR_get_rt_job_param		__LSC(11)
#define __NR_mark_event				__LSC(12)
#define __NR_null_call		        __LSC(13)
#define __NR_flush_cache            __LSC(14)
#define __NR_set_cos_ipi		    __LSC(15)
#define __NR_set_cos_lock		    __LSC(16)
#define __NR_rt_wrmsr   		    __LSC(17)
#define __NR_rt_rdmsr	    	    __LSC(18)
#define __NR_rt_wbinvd	    	    __LSC(19)
#define __NR_set_rt_task_cps         __LSC(20)
#define __NR_get_rt_task_cps         __LSC(21)

#define NR_litmus_syscalls 24
