#ifndef LITMUS_CACHE_PROC_H
#define LITMUS_CACHE_PROC_H

#include <asm/io.h>
#ifdef __KERNEL__
#include <linux/mm.h>

#if defined(CONFIG_XEN)
#include <asm/xen/page.h>
#endif

#if defined(CONFIG_ARM)
void litmus_setup_lockdown(void __iomem*, u32);
#endif

int __lock_cache_ways_to_cpu(int cpu, u32 ways_mask);
int lock_cache_ways_to_cpu(int cpu, u32 ways_mask);
int get_cache_ways_to_cpu(int cpu);
int unlock_all_cache_ways(void);
int lock_all_cache_ways(void);
int unlock_cache_ways_to_cpu(int cpu);
int __unlock_cache_ways_to_cpu(int cpu);
int __get_used_cache_ways_on_cpu(int cpu, uint16_t *cp_mask);

void flush_cache_ways(uint16_t ways);

#if defined(CONFIG_ARM)
void l2x0_flush_cache_ways(uint16_t ways);
#endif

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
void flush_cache_for_task(struct task_struct *tsk);
#endif

#define CACHE_MASK 0x0001f000
#define CACHE_SHIFT 12

unsigned int counting_one_set(unsigned long v);
unsigned int two_exp(unsigned int e);
unsigned int num_by_bitmask_index(unsigned long bitmask, unsigned int index);

struct page * get_colored_page(unsigned long color);

struct page * pick_one_colored_page(struct task_struct *target);
int detect_color_setting(struct task_struct *tsk, const char __user *const __user *envp);
int check_coloring_support(struct task_struct *target);

void dump_mm(struct mm_struct *mm);

extern unsigned long set_partition_min;
extern unsigned long set_partition_max;

static inline unsigned int page_color(struct page *page)
{
    //TODO: defferent call for converting page address to physical address
    // under XEN environment
#if defined(CONFIG_XEN)
    /* translate pfn to mfn to get the true page color */
    return (((get_phys_to_machine(page_to_pfn(page)) << PAGE_SHIFT) & CACHE_MASK) >> CACHE_SHIFT);
    //printk("pfn: %x, mfn: %x, color: %x\n", page_to_pfn(page),
    //        get_phys_to_machine(page_to_pfn(page)), color);
#else
    return ((page_to_phys(page) & CACHE_MASK) >> CACHE_SHIFT);
#endif
}
#endif

#endif
