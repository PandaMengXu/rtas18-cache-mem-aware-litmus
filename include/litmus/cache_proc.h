#ifndef LITMUS_CACHE_PROC_H
#define LITMUS_CACHE_PROC_H

#ifdef __KERNEL__
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

unsigned int counting_one_set(unsigned long v);
unsigned int two_exp(unsigned int e);
unsigned int num_by_bitmask_index(unsigned long bitmask, unsigned int index);

struct page * get_colored_page(unsigned long color);

extern unsigned long set_partition_min;
extern unsigned long set_partition_max;


#endif

#endif
