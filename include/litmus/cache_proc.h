#ifndef LITMUS_CACHE_PROC_H
#define LITMUS_CACHE_PROC_H

#ifdef __KERNEL__
void litmus_setup_lockdown(void __iomem*, u32);

int __lock_cache_ways_to_cpu(int cpu, u32 ways_mask);
int lock_cache_ways_to_cpu(int cpu, u32 ways_mask);
int get_cache_ways_to_cpu(int cpu);
int unlock_all_cache_ways(void);
int unlock_cache_ways_to_cpu(int cpu);
int __unlock_cache_ways_to_cpu(int cpu);

#endif

#endif
