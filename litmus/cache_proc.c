#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/migrate.h>
#include <linux/bitmap.h>

#include <linux/percpu.h>
#include <linux/sched.h>
#include <litmus/litmus.h>
#include <litmus/jobs.h>
#include <litmus/sched_plugin.h>
#include <litmus/fp_common.h>
#include <litmus/sched_trace.h>
#include <litmus/trace.h>

#include <litmus/preempt.h>
#include <litmus/litmus_proc.h>
#include <litmus/rt_domain.h>

#include <litmus/sched_trace.h>
#include <litmus/cache_proc.h>
#include <litmus/budget.h>

#if defined(CONFIG_ARM)
#include <asm/hardware/cache-l2x0.h>
#endif

#include <asm/cacheflush.h>

#include <linux/uaccess.h>

#define MAX_CPUS   32 

/** MX: The value should depend on platform
 *  TODO: make this value configurable */
#if defined(CONFIG_ARM)
static u32 lock_all_value = 0x0000ffff;
static u32 unlock_all_value = 0x00000000;
static u32 max_nr_ways = 16;
static u32 nr_cpu_sockets = 1;
static u32 nr_cores_per_socket = 4;
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
/* We assume the machine has CAT capability and 20 cache partitions */
static u32 lock_all_value = 0xfffff;
static u32 unlock_all_value = 0x00000;
static u32 max_nr_ways = 20;
static u32 nr_cpu_sockets = 1;
static u32 nr_cores_per_socket = 4;
#endif

static u32 way_partitions[MAX_CPUS];

#if defined(CONFIG_ARM)
static void __iomem *cache_base;
static void __iomem *lockreg_d;
static void __iomem *lockreg_i;

static u32 cache_id;

struct mutex actlr_mutex;
struct mutex l2x0_prefetch_mutex;
#endif
struct mutex lockdown_proc;

static u32 way_partition_min;
static u32 way_partition_max;

static int zero = 0;
static int one = 1;

////////////////////////////////////////////////////////
//page coloring
///////////////////////////////////////////////////////

static int pages_per_color = 0; // set as zero not to crash on boot
static int pages_per_color_min = 0;
static int pages_per_color_max = 1048576; // 1M x 4KB pages = 4GB per color

static u32 max_nr_sets = 32;

static unsigned long set_active_mask = 0;
unsigned long set_partition_min;
unsigned long set_partition_max;

static int show_page_pool = 0;
static int refill_page_pool = 0;

static struct mutex void_lockdown_proc;

struct color_group {
    spinlock_t lock;
    struct list_head list;
    atomic_t nr_pages;
};

static struct color_group *color_groups;

static int __init set_active_mask_setup(char *str)
{
    int ret;

    dbprintk("%s: called\n", __FUNCTION__);
    set_active_mask = 0xffffffff;
    if (sscanf(str, "0x%lx", &set_active_mask) != 1) {
        ret = bitmap_parselist(str, &set_active_mask, max_nr_sets);

        if (ret != 0) {
            printk(KERN_ERR "Wrong formatted active_colors: %s\n",
                str);
        }
    }

    printk(KERN_INFO "bootparam: set_active_mask=0x%lx\n", 
        set_active_mask);

    return 1;
}

__setup("active_colors=", set_active_mask_setup);

unsigned int counting_one_set(unsigned long v)
{
    unsigned int c;
    
    for (c = 0; v; v >>= 1) {
        c += v & 1;
    }

    return c;
}

unsigned int two_exp(unsigned int e)
{
    unsigned int v = 1;

    for (; e > 0; e--) {
        v = v * 2;
    }

    return v;
}

unsigned int num_by_bitmask_index(unsigned long bitmask, unsigned int index)
{
    unsigned int pos = 0;

    while(true) {
        if (index == 0 && (bitmask & 1) == 1) {
            break;
        }
   
        if (index != 0 && (bitmask & 1) == 1) {
            index--;
        }

        pos ++;
        bitmask = bitmask >> 1;
    }

    return pos;
}

static unsigned long smallest_nr_pages(void)
{
    unsigned long i, min_pages;
    struct color_group *cgroup;

    min_pages = pages_per_color;

    for (i = 0; i < max_nr_sets; ++i) {
        if ((set_active_mask & (1 << i)) == 0) {
            continue;
        }

        cgroup = &color_groups[i];
        if (atomic_read(&cgroup->nr_pages) < min_pages) {
            min_pages = atomic_read(&cgroup->nr_pages);
        }
    }

    return min_pages;
}

static void show_nr_pages(void)
{
    unsigned long i;
    struct color_group *cgroup;

    printk("Show nr pages*******************************\n");
    for (i = 0; i < max_nr_sets; ++i) {
        cgroup = &color_groups[i];
        printk("(%03lu) = %03d, " , i, atomic_read(&cgroup->nr_pages));
        if ((i % 8) == 7) {
            printk("\n");
        }
    }
}

static void add_page_to_color_list(struct page *page)
{
    const unsigned long color = page_color(page);
    struct color_group *cgroup = &color_groups[color];

    dbprintk("%s: called\n", __FUNCTION__);
    BUG_ON(in_list(&page->lru) || PageLRU(page));
    BUG_ON(page_count(page) > 1);
    
    spin_lock(&cgroup->lock);
    list_add_tail(&page->lru, &cgroup->list);
    atomic_inc(&cgroup->nr_pages);
    SetPageLRU(page);
    spin_unlock(&cgroup->lock);
}

static spinlock_t add_pages_lock;

static int do_add_pages(void)
{
    struct page *page, *page_tmp;
    LIST_HEAD(free_later);
    unsigned long color;
    int ret = 0;
    int i = 0;
    int counter[32] = {0,};
    int free_counter = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    if (!spin_trylock(&add_pages_lock)) {
        printk("In adding pages already\n");
        goto out;
    }

    while(smallest_nr_pages() < pages_per_color) {
        page = alloc_page(GFP_HIGHUSER_MOVABLE);

        if (unlikely(!page)) {
            printk(KERN_WARNING "Could not allocate pages.\n");
            ret = -ENOMEM;
            goto out_unlock;
        }

        color = page_color(page);

        if ((set_active_mask & (1 << color)) != 0 &&
            atomic_read(&color_groups[color].nr_pages) < pages_per_color) {
            add_page_to_color_list(page);
            counter[color]++;
        }
        else {
            list_add_tail(&page->lru, &free_later);
            free_counter++;
        }
    }

    for (i = 0; i < 32; ++i) {
        if (counter[i] > 0) {
            printk("pages added to color %d: %d\n", i, counter[i]);
        }
    }
    printk("freed = %d\n", free_counter);

    list_for_each_entry_safe(page, page_tmp, &free_later, lru) {
        list_del(&page->lru);
        __free_page(page);
    }

    show_nr_pages();

out_unlock:
    spin_unlock(&add_pages_lock);

out:
    return ret;
}

static struct page *new_alloc_page_color(unsigned long color)
{
    struct color_group *cgroup;
    struct page *rPage = NULL;

    dbprintk("%s: called\n", __FUNCTION__);
    if ((color < 0) || (color >= max_nr_sets)) {
        TRACE_CUR("Wrong color %lu\n", color);
        goto out;
    }

    if ((set_active_mask & (1 << color)) == 0) {
        TRACE_CUR("Request for deactivated color %lu\n", color);
        goto out;
    }

    cgroup = &color_groups[color];
    spin_lock(&cgroup->lock);
    if (unlikely(!atomic_read(&cgroup->nr_pages))) {
        TRACE_CUR("No free %lu colored pages.\n", color);
        goto out_unlock;
    }

    rPage = list_first_entry(&cgroup->list, struct page, lru);
    BUG_ON(page_count(rPage) > 1);
    list_del(&rPage->lru);
    atomic_dec(&cgroup->nr_pages);
    ClearPageLRU(rPage);

out_unlock:
    spin_unlock(&cgroup->lock);
out:
    //if (smallest_nr_pages() < PAGES_PER_COLOR / 2 ) {
    //    do_add_pages();
    //}

    return rPage;
}

struct page* get_colored_page(unsigned long color)
{
    dbprintk("%s: called\n", __FUNCTION__);
    return new_alloc_page_color(color);
}

static int do_resize_pages(void)
{
    unsigned long color;
    struct page *page, *page_tmp;
    LIST_HEAD(free_later);
    
    dbprintk("%s: called\n", __FUNCTION__);
    for (color = 0; color < max_nr_sets; ++color) {

        if ((set_active_mask & (1 << color)) == 0) {
            continue;
        }

        while(atomic_read(&color_groups[color].nr_pages) > pages_per_color) {
            page = new_alloc_page_color(color);

            list_add_tail(&page->lru, &free_later);
        }    
    }

    list_for_each_entry_safe(page, page_tmp, &free_later, lru) {
        list_del(&page->lru);
        __free_page(page);
    }

    do_add_pages();

    show_nr_pages();

    return 0;
}

int check_coloring_support(struct task_struct *target)
{
    unsigned long colors;
    
    if (target == NULL) {
        return 0;
    }

    colors = tsk_rt(target)->task_params.page_colors;

    if (colors < set_partition_min || colors > set_partition_max) {
        return 0;
    }

    return 1;
}

struct page* pick_one_colored_page(struct task_struct *target)
{
    unsigned long colors, color;
    unsigned int count;
    unsigned int index;
    struct page *rPage;

    colors = tsk_rt(target)->task_params.page_colors;
    index = tsk_rt(target)->task_params.color_index;

    dbprintk("%s: called\n", __FUNCTION__);
    if ((colors & set_active_mask) != colors) {
        printk("Using deactivated colors 0x%lx\n", colors);
        colors = colors & set_active_mask;
    }

    count = counting_one_set(colors);
    index = index % count;

    color = num_by_bitmask_index(colors, index);

    index = (index + 1) % count;

    rPage = get_colored_page(color);

    tsk_rt(target)->task_params.color_index = index;

    //printk("Pick a page: PID=%d colors=0x%lx color=%ld\n", target->pid, colors, color);

    return rPage;
}

static const char *ENVIRON_COLOR_SETTING = "PAGE_COLORS=";
#define ENV_BUF_LEN 30

int detect_color_setting(struct task_struct *tsk, const char __user *const __user *envp)
{
    char env_buf[ENV_BUF_LEN];
    const char __user *str;
    int len;
    int ret = 0;
    unsigned long page_colors;

    if (!tsk) {
        return 0;
    }

    while(true) {
        if (get_user(str, envp++)) {
            ret = -EFAULT;
            break;
        }

        if (!str) {
            break;
        }

        len = strnlen_user(str, ENV_BUF_LEN);
        if (!len) {
            ret = -EFAULT;
            break;
        }

        if (len > ENV_BUF_LEN) {
            len = ENV_BUF_LEN;
        }

        if (copy_from_user(env_buf, str, len)) {
            ret = -EFAULT;
            break;
        }

        env_buf[len - 1] = '\0';

        if (memcmp(env_buf, ENVIRON_COLOR_SETTING, 12) == 0) {
            if (sscanf(env_buf + 12, "0x%lx", &page_colors) == 1 ||
                sscanf(env_buf + 12, "%ld", &page_colors) == 1) {
                printk("Detect page_colors = 0x%lx\n", page_colors);

                if ((page_colors & set_active_mask) != page_colors) {
                    page_colors = page_colors & set_active_mask;
                    printk("Deactivated color index found. adjust=0x%lx\n",
                        page_colors);
                }

                if (page_colors == 0) {
                    printk("NOT VALID COLOR SETTING (0x%lx)\n", 
                        page_colors);
                    ret = -EINVAL;
                    break;
                }

                tsk->rt_param.task_params.page_colors = page_colors;
                tsk->rt_param.task_params.color_index = 0;
            }
            else {
                printk("invalid page_colors format: %s\n", env_buf);
                ret = -EINVAL;
            }

            break;
        }

        if (fatal_signal_pending(current)) {
            ret = -ERESTARTNOHAND;
            break;
        }

        cond_resched();
    } 

    return ret;
}

struct page *new_alloc_page(struct page *page, unsigned long color, int **x)
{
    struct page *rPage = NULL;

    dbprintk("%s: called\n", __FUNCTION__);
    rPage = new_alloc_page_color(color);

    return rPage;
}

static int show_page_pool_handler(struct ctl_table *table, int write, void __user *buffer,
        size_t *lenp, loff_t *ppos)
{
    int ret = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    mutex_lock(&void_lockdown_proc);
    ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
    if (ret)
        goto out;

    if (write) {
        show_nr_pages();
    }

out:
    mutex_unlock(&void_lockdown_proc);
    return ret;
}

static int refill_page_pool_handler(struct ctl_table *table, int write, void __user *buffer,
        size_t *lenp, loff_t *ppos)
{
    int ret = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    mutex_lock(&void_lockdown_proc);
    ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
    if (ret)
        goto out;

    if (write) {
        do_add_pages();
    }

out:
    mutex_unlock(&void_lockdown_proc);
    return ret;
}

static int pages_per_color_handler(struct ctl_table *table, int write, void __user *buffer,
        size_t *lenp, loff_t *ppos)
{
    int ret = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    mutex_lock(&void_lockdown_proc);
    ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
    if (ret)
        goto out;

    if (write) {
        do_resize_pages();
    }

out:
    mutex_unlock(&void_lockdown_proc);
    return ret;
}

static int __init init_color_groups(void)
{
    struct color_group *cgroup;
    unsigned long i;
    int err = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    printk("max_nr_set = %d\n", max_nr_sets);
    color_groups = kmalloc(max_nr_sets * sizeof(struct color_group), GFP_KERNEL);

    if (!color_groups) {
        printk(KERN_WARNING "Could not allocate color groups.\n");
        err = -ENOMEM;
    }
    else {
        for (i = 0; i < max_nr_sets; ++i) {
            cgroup = &color_groups[i];
            atomic_set(&cgroup->nr_pages, 0);
            INIT_LIST_HEAD(&cgroup->list);
            spin_lock_init(&cgroup->lock);
        }
    }

    return err;
}

static int __init init_page_coloring(void)
{
    unsigned int i;
    int err = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    max_nr_sets = counting_one_set(CACHE_MASK);
    max_nr_sets = two_exp(max_nr_sets);

    printk("MAX_NR_SETS=%d\n", max_nr_sets);

    set_partition_min = 0x00000001;
    set_partition_max = 0L;

    for (i = 0; i < max_nr_sets; ++i) {
        set_partition_max |= (1L << i);
    }

    printk("SET_MIN=%lu(0x%lx), SET_MAX=%lu(0x%lx)\n",
        set_partition_min, set_partition_min,
        set_partition_max, set_partition_max);

    //set_active_mask should be initialized by boot_param
    //if not, initialize as max
    if (set_active_mask == 0) {
        set_active_mask = set_partition_max;
    }
    else {
        //filter out
        set_active_mask &= set_partition_max;
    }

    printk("set_active_mask=0x%lx\n", set_active_mask);

    mutex_init(&void_lockdown_proc);

    spin_lock_init(&add_pages_lock);

    init_color_groups();
    do_add_pages();

    show_nr_pages();

    return err;
}

extern int isolate_lru_page(struct page *page);
extern void putback_lru_page(struct page *page);

// systemcall set_page_color
asmlinkage long sys_set_page_color(int cpu)
{
    long ret = 0;
    struct page *page_itr = NULL;
    struct vm_area_struct *vma_itr = NULL;
    int nr_pages = 0, nr_shared_pages = 0, nr_failed = 0;
    unsigned long node;

    dbprintk("%s: called\n", __FUNCTION__);
    LIST_HEAD(pagelist);
    LIST_HEAD(shared_pagelist);

    down_read(&current->mm->mmap_sem);
    TRACE_TASK(current, "SYSCALL set_page_color\n");
    vma_itr = current->mm->mmap;
    while(vma_itr != NULL) {
        unsigned int num_pages = 0, i;
        struct page *old_page = NULL;

        num_pages = (vma_itr->vm_end - vma_itr->vm_start) / PAGE_SIZE;

        for (i = 0; i < num_pages; ++i) {
            old_page = follow_page(vma_itr, vma_itr->vm_start + PAGE_SIZE * i,
                FOLL_GET|FOLL_SPLIT);

            if (IS_ERR(old_page))
                continue;

            if (!old_page)
                continue;

            if (PageReserved(old_page)) {
                TRACE("Reserved Page!\n");
                put_page(old_page);
                continue;
            }

            TRACE_TASK(current, "addr: %08x, pfn: %x, _maccount: %d, _count: %d\n",
                vma_itr->vm_start + PAGE_SIZE * i,
                __page_to_pfn(old_page),
                page_mapcount(old_page),
                page_count(old_page));

            if (page_mapcount(old_page) != 0) {
                ret = isolate_lru_page(old_page);
                if (!ret) {
                    list_add_tail(&old_page->lru, &pagelist);
                    inc_zone_page_state(old_page, NR_ISOLATED_ANON + !PageSwapBacked(old_page));
                    nr_pages++;
                }
                else {
                    TRACE_TASK(current, "isolate_lru_page failed.\n");
                    /** TODO: fix the compilation error */
                    //TRACE_TASK(current, "page_lru = %d PageLRU = %d\n",
                    //    page_lru(old_page), PageLRU(old_page));
                    nr_failed++;
                }
            }
            else  {
                ret = isolate_lru_page(old_page);
                if (!ret) {
                    list_add_tail(&old_page->lru, &shared_pagelist);
                    inc_zone_page_state(old_page, NR_ISOLATED_ANON + !PageSwapBacked(old_page));
                }

                nr_shared_pages++;
                put_page(old_page);
            }
        }

        vma_itr = vma_itr->vm_next;
    }

    ret = 0;
    node = cpu;

    if (!list_empty(&pagelist)) {
        ret = migrate_pages(&pagelist, new_alloc_page, node, MIGRATE_ASYNC, MR_SYSCALL);
        TRACE_TASK(current, "%ld pages not migrated\n", ret);
        if (ret) {
            putback_lru_pages(&pagelist);
        }
    }

   up_read(&current->mm->mmap_sem);

    list_for_each_entry(page_itr, &shared_pagelist, lru) {
        TRACE("S Anon=%d pfn=%lu, _mapcount=%d, _count=%d\n",
            PageAnon(page_itr),
            __page_to_pfn(page_itr),
            page_mapcount(page_itr),
            page_count(page_itr));
    }

    TRACE_TASK(current, "nr_pages=%d, nr_failed=%d\n", nr_pages, nr_failed);
    printk(KERN_INFO "node=%ld, nr_pages=%d, nr_failed=%d\n",
        node, nr_pages, nr_failed);

    return ret;
}

//////////////////////////////////////////////////////////

#if defined(CONFIG_ARM)
static int l1_prefetch_proc;
static int l2_prefetch_hint_proc;
static int l2_double_linefill_proc;
static int l2_data_prefetch_proc;

#define ld_d_reg(cpu) ({ int __cpu = cpu; \
			void __iomem *__v = cache_base + L2X0_LOCKDOWN_WAY_D_BASE + \
			__cpu * L2X0_LOCKDOWN_STRIDE; __v; })
#define ld_i_reg(cpu) ({ int __cpu = cpu; \
			void __iomem *__v = cache_base + L2X0_LOCKDOWN_WAY_I_BASE + \
			__cpu * L2X0_LOCKDOWN_STRIDE; __v; })
#endif

int lock_all;
int nr_lockregs;

#if defined(CONFIG_ARM)
static raw_spinlock_t cache_lock;
static raw_spinlock_t prefetch_lock;
#endif /* CONFIG_ARM */

int pid;
int rt_pid_min;
int rt_pid_max;
uint16_t new_cp_status;
uint16_t rt_cp_min;
uint16_t rt_cp_max;

#if defined(CONFIG_ARM)
extern void l2x0_flush_all(void);
#endif

void flush_cache_ways(uint16_t ways)
{
#if defined(CONFIG_ARM)
    l2x0_flush_cache_ways(ways);
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
    dbprintk("%s: ERROR: x86 cannot flush a cache way\n", __FUNCTION__);
#warning TODO: implement flush_cache_ways
#endif
}

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)

// 0: exclude the code area from flushing
static int flushing_code = 1;
static raw_spinlock_t flushing_code_lock;

int flushing_code_handler(struct ctl_table *table, int write,
        void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;

    dbprintk("%s: called\n", __FUNCTION__);
    raw_spin_lock(&flushing_code_lock);	
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
    raw_spin_unlock(&flushing_code_lock);

	return ret;
}

#if 0
static void local_clflush(void *vaddr)
{
    asm volatile ("clflush (%0)" :: "r"(vaddr));
}

static void local_clflush_cache_range(void *vaddr, unsigned int size)
{
    unsigned long clflush_mask = boot_cpu_data.x86_clflush_size - 1;
    void *vend = vaddr + size;
    void *p;

    mb();

    for (p = (void *)((unsigned long)vaddr & ~clflush_mask);
      p < vend; p += boot_cpu_data.x86_clflush_size) {
        local_clflush(p);
    }

    mb();
}
#endif

void flush_cache_for_task(struct task_struct *tsk)
{
    struct vm_area_struct *vma_itr = NULL;
    int nr_pages = 0;

    dbprintk("%s: called\n", __FUNCTION__);
    raw_spin_lock(&flushing_code_lock);

    down_read(&tsk->mm->mmap_sem);
    TRACE_TASK(tsk, "FLUSH_CACHE_FOR_TASK\n");
    vma_itr = tsk->mm->mmap;

    while (vma_itr != NULL) {
        unsigned int num_pages = 0, i;
        struct page *cur_page = NULL;
        unsigned long addr;

        if ( !(vma_itr->vm_flags & (VM_READ | VM_WRITE)) )
            goto next;
        if ( !flushing_code && (vma_itr->vm_flags & VM_EXEC) )
            goto next;
#if 0
        num_pages = (vma_itr->vm_end - vma_itr->vm_start) / PAGE_SIZE;

        for (i = 0; i < num_pages; ++i) {
            addr = vma_itr->vm_start + PAGE_SIZE * i;

            /* Walk page table to determine if 
             * the addr is mapped to a valid mem */
            cur_page = follow_page(vma_itr, 
                    addr,
                    FOLL_GET|FOLL_SPLIT);

            if (IS_ERR(cur_page)) {
                continue;
            }

            if (!cur_page) {
                continue;
            }

            if (PageReserved(cur_page)) {
                TRACE("Reserved Page!\n");
                put_page(cur_page);
                continue;
            }

            TRACE_TASK(tsk, "addr: 0x%08x, pfn: 0x%x, "
                            "_mapcount: %d, _count: %d\n",
                    addr,
                    __page_to_pfn(cur_page),
                    page_mapcount(cur_page),
                    page_count(cur_page));

            clflush_cache_range(addr, PAGE_SIZE);
            //local_clflush_cache_range((void *)addr, PAGE_SIZE);

            put_page(cur_page);
        }
#else   /* NB: This one may not be working */
        dbprintk("%s: flush [0x%016lx - 0x%016lx)\n", __FUNCTION__,
                 vma_itr->vm_start, vma_itr->vm_end);
        clflush_cache_range(vma_itr->vm_start, vma_itr->vm_end - vma_itr->vm_start);
#endif
next:
        vma_itr = vma_itr->vm_next;
    }

    up_read(&tsk->mm->mmap_sem);

    raw_spin_unlock(&flushing_code_lock);
}
#endif

static void print_lockdown_registers(int cpu)
{
#if defined(CONFG_ARM)
	int i;
	for (i = 0; i < nr_lockregs; i++) {
		dbprintk("P%d Lockdown Data CPU %2d: 0x%04x\n", cpu,
				i, readl_relaxed(ld_d_reg(i)));
		dbprintk("P%d Lockdown Inst CPU %2d: 0x%04x\n", cpu,
				i, readl_relaxed(ld_i_reg(i)));
	}
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
#define COS_REG_BASE    0xc90
#define PQR_REG     0xC8F

    int socket_i, core_i, cpu_i, cos_i;
    u32 data[2];
   
	memset(data, 0, sizeof(data));
    for (socket_i = 0; socket_i < nr_cpu_sockets; ++socket_i) {
        for(core_i = 0; core_i < nr_cores_per_socket; ++core_i) {
            cpu_i = socket_i * nr_cores_per_socket + core_i;
            cos_i = core_i;

            if (cos_i >= nr_lockregs) {
                cos_i = nr_lockregs - 1;
            }

            rdmsr_safe_on_cpu(cpu_i, PQR_REG, &data[0], &data[1]);
            printk("P%d PQR %d (CPU %d) is using COS %d of cpu socket %d\n",
                cpu, cpu_i, cpu_i, data[1], socket_i);

            rdmsr_safe_on_cpu(cpu_i, COS_REG_BASE + cos_i, 
                &data[0], &data[1]);
            printk("P%d COS %d for CPU %d: 0x%08x\n",
                cpu, cos_i, cpu_i, data[0]);
        }
    }
#endif
}

#if defined(CONFIG_ARM)
static void test_lockdown(void *ignore)
{
	int i, cpu;

	cpu = smp_processor_id();
	printk("Start lockdown test on CPU %d.\n", cpu);

	for (i = 0; i < nr_lockregs; i++) {
		printk("CPU %2d data reg: 0x%8p\n", i, ld_d_reg(i));
		printk("CPU %2d inst reg: 0x%8p\n", i, ld_i_reg(i));
	}

	printk("Lockdown initial state:\n");
	print_lockdown_registers(cpu);
	printk("---\n");

	for (i = 0; i < nr_lockregs; i++) {
		writel_relaxed(1, ld_d_reg(i));
		writel_relaxed(2, ld_i_reg(i));
	}
	printk("Lockdown all data=1 instr=2:\n");
	print_lockdown_registers(cpu);
	printk("---\n");

	for (i = 0; i < nr_lockregs; i++) {
		writel_relaxed((1 << i), ld_d_reg(i));
		writel_relaxed(((1 << 8) >> i), ld_i_reg(i));
	}
	printk("Lockdown varies:\n");
	print_lockdown_registers(cpu);
	printk("---\n");

	for (i = 0; i < nr_lockregs; i++) {
		writel_relaxed(UNLOCK_ALL, ld_d_reg(i));
		writel_relaxed(UNLOCK_ALL, ld_i_reg(i));
	}
	printk("Lockdown all zero:\n");
	print_lockdown_registers(cpu);

	printk("End lockdown test.\n");
}
#endif

#if defined(CONFIG_ARM)
void litmus_setup_lockdown(void __iomem *base, u32 id)
{
	cache_base = base;
	cache_id = id;
	lockreg_d = cache_base + L2X0_LOCKDOWN_WAY_D_BASE;
	lockreg_i = cache_base + L2X0_LOCKDOWN_WAY_I_BASE;
    
    dbprintk("%s: called\n", __FUNCTION__);
	if (L2X0_CACHE_ID_PART_L310 == (cache_id & L2X0_CACHE_ID_PART_MASK)) {
		nr_lockregs = 8;
        max_nr_ways = 16;
        lock_all_value = 0x0000ffff;
        unlock_all_value = 0x00000000;
        nr_cpu_sockets = 1;
        nr_cores_per_socket = 4;
	} else {
		printk("Unknown cache ID!\n");
		nr_lockregs = 1;
        max_nr_ways = 16;
        lock_all_value = 0x0000ffff;
        unlock_all_value = 0x00000000;
        nr_cpu_sockets = 1;
        nr_cores_per_socket = 4;
	}
	
	mutex_init(&actlr_mutex);
	mutex_init(&l2x0_prefetch_mutex);
	mutex_init(&lockdown_proc);
	raw_spin_lock_init(&cache_lock);
	raw_spin_lock_init(&prefetch_lock);
	
	test_lockdown(NULL);
}
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)

#define CPUID_LEAF_EXT_FEATURES 0x07
#define CPU_EXT_FEATURE_PQE 0x00008000

#define CPUID_LEAF_CACHE_PARAMS 0x04
#define CPUID_COUNT_L3_PARAMS   0x03

#define L3_CACHE_LINE_SIZE_MASK 0x00000fff
#define L3_CACHE_LINE_PARTITION_MASK    0x003ff000
#define L3_CACHE_LINE_PARTITION_SHIFT    12
#define L3_CACHE_WAYS_SHIFT 22

#define CPUID_LEAF_CAT 0x10
#define CPUID_COUNT_CAT_RESOURCE_TYPE 0x00
#define CPUID_COUNT_CAT_CAPABILITY    0x01

#define CAT_L3_RESOURCE_TID_MASK 0x00000002
#define CAT_CBM_LEN_MASK         0x0000001f
#define CAT_CDP_SUPPORT_MASK     0x00000004
#define CAT_COS_MAX_MASK         0x0000ffff

static void detect_intel_cat_1(void)
{
    unsigned int eax, ebx, ecx, edx;

    dbprintk("%s: called\n", __FUNCTION__);
    // check L3 CAT Support
    cpuid_count(CPUID_LEAF_CAT, CPUID_COUNT_CAT_RESOURCE_TYPE,
        &eax, &ebx, &ecx, &edx);

    if (ebx & CAT_L3_RESOURCE_TID_MASK) {
        printk("CAT for L3 cache can be supported\n");
    }

    // check Capabilities of L3 CAT
    cpuid_count(CPUID_LEAF_CAT, CPUID_COUNT_CAT_CAPABILITY,
        &eax, &ebx, &ecx, &edx);

    max_nr_ways = (eax & CAT_CBM_LEN_MASK) + 1;

    nr_lockregs = (edx & CAT_COS_MAX_MASK) + 1;
}

static void detect_intel_cat_0(void)
{
    unsigned int line_size, line_partitions, way_count;
    unsigned int eax, ebx, ecx, edx;

    dbprintk("%s: called\n", __FUNCTION__);
    cpuid_count(CPUID_LEAF_CACHE_PARAMS, CPUID_COUNT_L3_PARAMS,
        &eax, &ebx, &ecx, &edx);

    line_size = (ebx & L3_CACHE_LINE_SIZE_MASK) + 1;
    line_partitions = ((ebx & L3_CACHE_LINE_PARTITION_MASK) 
        >> L3_CACHE_LINE_PARTITION_SHIFT) + 1;
    max_nr_ways = (ebx >> L3_CACHE_WAYS_SHIFT) + 1;

    // fixed value 
    nr_lockregs = 4;
}

static void detect_intel_cat(void) {
    int i;
    unsigned int eax, ebx, ecx, edx;
    struct cpuinfo_x86  *c;

    dbprintk("%s: called\n", __FUNCTION__);
    //check CAT configuration
    cpuid_count(CPUID_LEAF_EXT_FEATURES, 0x00,
        &eax, &ebx, &ecx, &edx);

    if (eax & CPU_EXT_FEATURE_PQE) {
        detect_intel_cat_1();
    }
    else {
        detect_intel_cat_0();
    }

    lock_all_value = 0x00000000;
    unlock_all_value = 0x00000000;

    for (i = 0; i < max_nr_ways; ++i) {
        lock_all_value |= (1 << i);
    }

    // number of cpu sockets
    c = &cpu_data(num_online_cpus() - 1);
    nr_cpu_sockets = c->phys_proc_id + 1;
    nr_cores_per_socket = num_online_cpus() / nr_cpu_sockets;

    printk("max_nr_ways = %d\n", max_nr_ways);
    printk("nr_lockregs = %d, nr_cpu_sockets = %d, nr_cores_per_socket = %d\n", 
        nr_lockregs, nr_cpu_sockets, nr_cores_per_socket);
    printk("lock_all = 0x%08x, unlock_all = 0x%08x\n",
        lock_all_value, unlock_all_value);
}

static void init_intel_cat(void)
{
    struct cpuinfo_x86 *c;
    int socket_i, core_i, cpu_i;
    u32 cos_i;

    dbprintk("%s: called\n", __FUNCTION__);
    for(socket_i = 0; socket_i < nr_cpu_sockets; ++socket_i) {
        for(core_i = 0; core_i < nr_cores_per_socket; ++core_i) {
            cpu_i = socket_i * nr_cores_per_socket + core_i;
            c = &cpu_data(cpu_i);
            cos_i = core_i;

            if (cos_i >= nr_lockregs) {
                // set to last COS
                cos_i = nr_lockregs - 1;
            }

            wrmsr_safe_on_cpu(cpu_i, PQR_REG, 0, cos_i);
        }
    }

    printk("INITIAL SETUP RESULT\n");
    print_lockdown_registers(smp_processor_id());
}

static void litmus_setup_msr(void)
{
    dbprintk("%s: called\n", __FUNCTION__);
    mutex_init(&lockdown_proc);
    raw_spin_lock_init(&flushing_code_lock);

    detect_intel_cat();

    //assign PQR to each COS
    init_intel_cat();

    way_partition_max = lock_all_value;
}
#endif /* CONFIG_ARM */

static int way_mask_sanity_check(u32 ways_mask)
{
    int ret = 0;
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    int i;    
    int count, start, end;
#endif

    dbprintk("%s: called\n", __FUNCTION__);
    if (ways_mask > way_partition_max) {
        ret = -EINVAL;
        printk(KERN_ERR "%s: caller tries to set cp: 0x%x\n", __FUNCTION__, ways_mask);
        goto out;
    }

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    /** must use at least 2 cache partitions
     */
    if ( hweight_long(ways_mask) < 2 )
    {
        printk(KERN_ERR "%s: ways_mask (0x%x) must have at least 2 bits set\n",
                 __FUNCTION__, ways_mask);
        ret = -EINVAL;
    }
    /** Check if cache partitions are continuous
      * Unnecessary */
    /**
    count = 0;
    start = -1;
    end = -1;
    for(i = 0; i < max_nr_ways; ++i) {
        if (ways_mask & (1 << i)) {
            count ++;

            if (start == -1) {
                start = i;
                end = i;
            }
            else {
                if (i == (end + 1)) {
                    end = i;
                }
                else {
                    ret = -EINVAL;
                    goto out;
                }
            }
        }
    }

    if (count < 2) {
        ret = -EINVAL;
    }
    */

#endif

out:
    return ret;
}

int __lock_cache_ways_to_cpu(int cpu, u32 ways_mask)
{
	int ret = 0;
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    int cos_i;
#endif
	
    dbprintk("%s: CPs set to 0x%x on P%d\n", __FUNCTION__,
              ways_mask, cpu);
    if ((ret = way_mask_sanity_check(ways_mask)) != 0) {
        printk(KERN_ERR "%s: does not pass way_mask_sanity_check: input (P%d 0x%x)\n",
               __FUNCTION__, cpu, ways_mask);
        goto out;
    }

	if (cpu < 0 || cpu >= num_online_cpus() || cpu >= MAX_CPUS) {
        printk(KERN_ERR "%s: input P%d out of range\n", __FUNCTION__, cpu);
		ret = -EINVAL;
		goto out;
	}

	way_partitions[cpu] = ways_mask;

    dbprintk("%s: Cache partitions 0x%x are initialized as available\n",
             __FUNCTION__, way_partitions[cpu]);
#if defined(CONFIG_ARM)
	writel_relaxed(~way_partitions[cpu], ld_d_reg(cpu));
	//writel_relaxed(~way_partitions[cpu*2], ld_i_reg(cpu));
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
    dbprintk("%s: set P%d cos to 0x%x...\n", __FUNCTION__,
             cpu, way_partitions[cpu]);
    cos_i = cpu % nr_cores_per_socket;

    if (cos_i >= nr_lockregs) {
        cos_i = nr_lockregs - 1;
        printk("[WARN] NO COS register for P%d, use COS %d for P%d\n", cpu, cos_i, cpu);
    }

    wrmsr_safe_on_cpu(cpu, COS_REG_BASE + cos_i, way_partitions[cpu], 0);
#endif
	
out:
	return ret;
}

int lock_cache_ways_to_cpu(int cpu, u32 ways_mask)
{
	int ret = 0;

    dbprintk("%s: called\n", __FUNCTION__);
	mutex_lock(&lockdown_proc);

	ret = __lock_cache_ways_to_cpu(cpu, ways_mask);

	mutex_unlock(&lockdown_proc);

	return ret;
}

int __unlock_cache_ways_to_cpu(int cpu)
{
    dbprintk("%s: P%d\n", __FUNCTION__, cpu);
#if defined(CONFIG_ARM)
	return __lock_cache_ways_to_cpu(cpu, 0x0);
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
	return __lock_cache_ways_to_cpu(cpu, lock_all_value);
#endif
}

int unlock_cache_ways_to_cpu(int cpu)
{
	int ret = 0;

	mutex_lock(&lockdown_proc);

	ret = __unlock_cache_ways_to_cpu(cpu);

	mutex_unlock(&lockdown_proc);

	return ret;
}

int __get_used_cache_ways_on_cpu(int cpu, uint16_t *cp_mask)
{
	int ret = 0;
	unsigned long flags;
	u32 ways_mask_i, ways_mask_d;
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    u32 data[2];
    int cos_i;    
#endif

    dbprintk("%s: called\n", __FUNCTION__);
	if (cpu < 0 || cpu >= num_online_cpus() || cpu >= MAX_CPUS) {
		ret = -EINVAL;
		goto out;
	}

#if defined(CONFIG_ARM)
	local_irq_save(flags);

	ways_mask_d = readl_relaxed(ld_d_reg(cpu));
	//ways_mask_i = readl_relaxed(ld_i_reg(cpu));
	local_irq_restore(flags);

	//if (ways_mask_i != ways_mask_d) {
	//	TRACE("Ways masks for I and D mismatch I=0x%04x, D=0x%04x\n", ways_mask_i, ways_mask_d);
	//	printk(KERN_ERR "Ways masks for I and D mismatch I=0x%04x, D=0x%04x\n", ways_mask_i, ways_mask_d);
	//	ret = ways_mask_i;
	//}
	*cp_mask = ((~ways_mask_d) & CACHE_PARTITIONS_MASK);

#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
    cos_i = cpu % nr_cores_per_socket;

    if (cos_i >= nr_lockregs) {
        cos_i = nr_lockregs - 1;
    }

    rdmsr_safe_on_cpu(cpu, COS_REG_BASE + cos_i, &data[0], &data[1]);

    *cp_mask = data[0];
#endif

out:
	return ret;
}

static int __get_cache_ways_to_cpu(int cpu)
{
	int ret = 0;
	unsigned long flags;
	u32 ways_mask_i, ways_mask_d;
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    u32 data[2];
    int cos_i;    
#endif
	
    dbprintk("%s: called\n", __FUNCTION__);
	if (cpu < 0 || cpu >= num_online_cpus() || cpu >= MAX_CPUS) {
		ret = -EINVAL;
		goto out;
	}

#if defined(CONFIG_ARM)
	local_irq_save(flags);
	ways_mask_d = readl_relaxed(ld_d_reg(cpu));
	//ways_mask_i = readl_relaxed(ld_i_reg(cpu));

	local_irq_restore(flags);

	//if (ways_mask_i != ways_mask_d) {
	//	printk(KERN_ERR "Ways masks for I and D mismatch I=0x%04x, D=0x%04x\n", ways_mask_i, ways_mask_d);
	ret = ways_mask_d;
	//}
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
    cos_i = cpu % nr_cores_per_socket;

    if (cos_i >= nr_lockregs) {
        cos_i = nr_lockregs - 1;
    }

    rdmsr_safe_on_cpu(cpu, COS_REG_BASE + cos_i, &data[0], &data[1]);

    ret = data[0];
#endif
out:
	return ret;
}

int get_cache_ways_to_cpu(int cpu)
{
	int ret = 0;
	
    dbprintk("%s: called\n", __FUNCTION__);
	mutex_lock(&lockdown_proc);

	ret = __get_cache_ways_to_cpu(cpu);

	mutex_unlock(&lockdown_proc);

	return ret;
}

static int __unlock_all_cache_ways(void)
{
	int ret = 0, i;

    dbprintk("%s: called\n", __FUNCTION__);
	for (i = 0; i < num_online_cpus(); ++i) {
#if defined(CONFIG_ARM)
	    return __lock_cache_ways_to_cpu(i, 0x0);
#elif defined(CONFIG_X86) || defined(CONFIG_X86_64)
	    return __lock_cache_ways_to_cpu(i, lock_all_value);
#endif
	}

	return ret;
}

int unlock_all_cache_ways(void)
{
	int ret = 0;
	
    dbprintk("%s: called\n", __FUNCTION__);
	mutex_lock(&lockdown_proc);

	ret = __unlock_all_cache_ways();

	mutex_unlock(&lockdown_proc);

	return ret;
}

static int __lock_all_cache_ways(void)
{
	int ret = 0, i;

    dbprintk("%s: called\n", __FUNCTION__);
	for (i = 0; i < num_online_cpus(); ++i) {
        __lock_cache_ways_to_cpu(i, lock_all_value);
	}

	return ret;
}

int lock_all_cache_ways(void)
{
	int ret = 0;
	
    dbprintk("%s: called\n", __FUNCTION__);
	mutex_lock(&lockdown_proc);

	ret = __lock_all_cache_ways();

	mutex_unlock(&lockdown_proc);

	return ret;
}


int way_partition_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;
	
    dbprintk("%s: called\n", __FUNCTION__);
	mutex_lock(&lockdown_proc);
	
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write) {
		printk("Way-partition settings:\n");
		for (i = 0; i < num_online_cpus(); i++) {
			printk("0x%08X\n", way_partitions[i]);
		}
		for (i = 0; i < num_online_cpus(); i++) {
			__lock_cache_ways_to_cpu(i, way_partitions[i]);
		}
	}
	
	local_irq_save(flags);
	print_lockdown_registers(smp_processor_id());
	local_irq_restore(flags);

out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

int cache_status_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0;
	rt_domain_t *rt = &gsnfpca;
	
    dbprintk("%s: called\n", __FUNCTION__);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write) {
		printk("Change rt.used_cache_partitions to 0x%x:\n", new_cp_status);
		raw_spin_lock(&rt->ready_lock);
		rt->used_cache_partitions = new_cp_status;
		printk("New rt.used_cache_partitions 0x%x:\n", rt->used_cache_partitions);
		raw_spin_unlock(&rt->ready_lock);
	} else {
		raw_spin_lock(&rt->ready_lock);
		printk("rt.used_cache_partitions 0x%x:\n", rt->used_cache_partitions);
		raw_spin_unlock(&rt->ready_lock);
	}
	
out:
	return ret;
}

int task_info_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0;
	struct task_struct *task;
	int out_of_time, sleep, np, blocks, on_release;
	rt_domain_t *rt = &gsnfpca;
	
    dbprintk("%s: called\n", __FUNCTION__);
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;

	if (write) {
		printk("task pid %d\n", pid);
		if (pid < 1 || pid > 10000)
		{
			printk("valid pid:1-10000\n");
			goto out;
		}
		task = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (!task)
		{
			printk("get_pid_task: pid is null\n");
		}
		blocks      = !is_running(task);
		out_of_time = budget_enforced(task)
			&& budget_exhausted(task);
		np 	    = is_np(task);
		sleep	    = is_completed(task);
		on_release = !list_empty(&tsk_rt(task)->list);
		printk("task %s/%d/%d = (%lld %lld %d)\n"
           "color:0x%08lx color_index:%d "
		   "blocks:%d out_of_time:%d np:%d sleep:%d "
		   "state:%d sig:%d on_release_q:%d cp:0x%x rt.cp:0x%x "
		   "scheduled_on:%ld linked_on:%d "
		   "release_at:%lldns now:%lldns\n",
		   task->comm, task->pid, tsk_rt(task)->job_params.job_no,
		   tsk_rt(task)->task_params.period,
		   tsk_rt(task)->task_params.exec_cost,
		   tsk_rt(task)->task_params.num_cache_partitions,
           tsk_rt(task)->task_params.page_colors,
           tsk_rt(task)->task_params.color_index,
		   blocks, out_of_time, np, sleep,
		   task->state, signal_pending(task),
		   on_release,
		   tsk_rt(task)->job_params.cache_partitions,
		   rt->used_cache_partitions,
		   tsk_rt(task)->scheduled_on, tsk_rt(task)->linked_on,
		   get_release(task), litmus_clock());
	}

out:
	return ret;
}

int lock_all_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;
	
    dbprintk("%s: called\n", __FUNCTION__);
	mutex_lock(&lockdown_proc);
	
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	
	if (write && lock_all == 1) {
        lock_all_cache_ways();
	}
	if (write && lock_all == 0) {
        unlock_all_cache_ways();
	}
	printk("LOCK_ALL HANDLER\n");
	local_irq_save(flags);
	print_lockdown_registers(smp_processor_id());
	local_irq_restore(flags);
out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

#if defined(CONFIG_ARM)

/* Operate on the Cortex-A9's ACTLR register */
#define ACTLR_L2_PREFETCH_HINT	(1 << 1)
#define ACTLR_L1_PREFETCH	(1 << 2)

/*
 * Change the ACTLR.
 * @mode	- If 1 (0), set (clear) the bit given in @mask in the ACTLR.
 * @mask	- A mask in which one bit is set to operate on the ACTLR.
 */
static void actlr_change(int mode, int mask)
{
	u32 orig_value, new_value, reread_value;

	if (0 != mode && 1 != mode) {
		printk(KERN_WARNING "Called %s with mode != 0 and mode != 1.\n",
				__FUNCTION__);
		return;
	}

	/* get the original value */
	asm volatile("mrc p15, 0, %0, c1, c0, 1" : "=r" (orig_value));

	if (0 == mode)
		new_value = orig_value & ~(mask);
	else
		new_value = orig_value | mask;

	asm volatile("mcr p15, 0, %0, c1, c0, 1" : : "r" (new_value));
	asm volatile("mrc p15, 0, %0, c1, c0, 1" : "=r" (reread_value));

	printk("ACTLR: orig: 0x%8x  wanted: 0x%8x  new: 0x%8x\n",
			orig_value, new_value, reread_value);
}

int litmus_l1_prefetch_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&actlr_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if (!ret && write) {
		mode = *((int*)table->data);
		actlr_change(mode, ACTLR_L1_PREFETCH);
	}
	mutex_unlock(&actlr_mutex);

	return ret;
}

int litmus_l2_prefetch_hint_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&actlr_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!ret && write) {
		mode = *((int*)table->data);
		actlr_change(mode, ACTLR_L2_PREFETCH_HINT);
	}
	mutex_unlock(&actlr_mutex);

	return ret;
}


/* Operate on the PL-310's Prefetch Control Register, L2X0_PREFETCH_CTRL */
#define L2X0_PREFETCH_DOUBLE_LINEFILL	(1 << 30)
#define L2X0_PREFETCH_INST_PREFETCH	(1 << 29)
#define L2X0_PREFETCH_DATA_PREFETCH	(1 << 28)
static void l2x0_prefetch_change(int mode, int mask)
{
	u32 orig_value, new_value, reread_value;

	if (0 != mode && 1 != mode) {
		printk(KERN_WARNING "Called %s with mode != 0 and mode != 1.\n",
				__FUNCTION__);
		return;
	}

	orig_value = readl_relaxed(cache_base + L2X0_PREFETCH_CTRL);

	if (0 == mode)
		new_value = orig_value & ~(mask);
	else
		new_value = orig_value | mask;

	writel_relaxed(new_value, cache_base + L2X0_PREFETCH_CTRL);
	reread_value = readl_relaxed(cache_base + L2X0_PREFETCH_CTRL);

	printk("l2x0 prefetch: orig: 0x%8x  wanted: 0x%8x  new: 0x%8x\n",
			orig_value, new_value, reread_value);
}

int litmus_l2_double_linefill_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&l2x0_prefetch_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!ret && write) {
		mode = *((int*)table->data);
		l2x0_prefetch_change(mode, L2X0_PREFETCH_DOUBLE_LINEFILL);
	}
	mutex_unlock(&l2x0_prefetch_mutex);

	return ret;
}

int litmus_l2_data_prefetch_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&l2x0_prefetch_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!ret && write) {
		mode = *((int*)table->data);
		l2x0_prefetch_change(mode, L2X0_PREFETCH_DATA_PREFETCH|L2X0_PREFETCH_INST_PREFETCH);
	}
	mutex_unlock(&l2x0_prefetch_mutex);

	return ret;
}

#endif /* CONFIG_ARM */

#define DEFINE_WAY_HANDLER(cpu) \
	{ \
		.procname	= "C" #cpu "_LA_way", \
		.mode		= 0666, \
		.proc_handler	= way_partition_handler, \
		.data		= &way_partitions[cpu], \
		.maxlen		= sizeof(way_partitions[cpu]), \
		.extra1		= &way_partition_min, \
		.extra2		= &way_partition_max, \
	}
static struct ctl_table cache_table[] =
{
	{
		.procname	= "lock_all",
		.mode		= 0666,
		.proc_handler	= lock_all_handler,
		.data		= &lock_all,
		.maxlen		= sizeof(lock_all),
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "task_info",
		.mode		= 0666,
		.proc_handler	= task_info_handler,
		.data		= &pid,
		.maxlen		= sizeof(pid),
		.extra1		= &rt_pid_min,
		.extra2		= &rt_pid_max,
	},	
	{
		.procname	= "rt_used_cp",
		.mode		= 0666,
		.proc_handler	= cache_status_handler,
		.data		= &new_cp_status,
		.maxlen		= sizeof(pid),
		.extra1		= &rt_cp_min,
		.extra2		= &rt_cp_max,
	},	
    {
        .procname   = "show_page_pool",
        .mode       = 0666,
        .proc_handler = show_page_pool_handler,
        .data       = &show_page_pool,
        .maxlen    = sizeof(show_page_pool),
    },
    {
        .procname   = "refill_page_pool",
        .mode       = 0666,
        .proc_handler = refill_page_pool_handler,
        .data       = &refill_page_pool,
        .maxlen    = sizeof(refill_page_pool),
    },
    {
        .procname   = "pages_per_color",
        .mode       = 0666,
        .proc_handler = pages_per_color_handler,
        .data       = &pages_per_color,
        .maxlen    = sizeof(pages_per_color),
        .extra1     = &pages_per_color_min,
        .extra2     = &pages_per_color_max,
    },
    {
        .procname   = "flushing_code",
        .mode       = 0666,
        .proc_handler = flushing_code_handler,
        .data       = &flushing_code,
        .maxlen     = sizeof(flushing_code),
        .extra1     = &zero,
        .extra2     = &one,
    },
#if defined(CONFIG_ARM)
	{
		.procname	= "l1_prefetch",
		.mode		= 0644,
		.proc_handler	= litmus_l1_prefetch_proc_handler,
		.data		= &l1_prefetch_proc,
		.maxlen		= sizeof(l1_prefetch_proc),
	},
	{
		.procname	= "l2_prefetch_hint",
		.mode		= 0644,
		.proc_handler	= litmus_l2_prefetch_hint_proc_handler,
		.data		= &l2_prefetch_hint_proc,
		.maxlen		= sizeof(l2_prefetch_hint_proc),
	},
	{
		.procname	= "l2_double_linefill",
		.mode		= 0644,
		.proc_handler	= litmus_l2_double_linefill_proc_handler,
		.data		= &l2_double_linefill_proc,
		.maxlen		= sizeof(l2_double_linefill_proc),
	},
	{
		.procname	= "l2_data_prefetch",
		.mode		= 0644,
		.proc_handler	= litmus_l2_data_prefetch_proc_handler,
		.data		= &l2_data_prefetch_proc,
		.maxlen		= sizeof(l2_data_prefetch_proc),
	},
#endif /* CONFIG_ARM */
    DEFINE_WAY_HANDLER(0),
    DEFINE_WAY_HANDLER(1),
    DEFINE_WAY_HANDLER(2),
    DEFINE_WAY_HANDLER(3),
    DEFINE_WAY_HANDLER(4),
    DEFINE_WAY_HANDLER(5),
    DEFINE_WAY_HANDLER(6),
    DEFINE_WAY_HANDLER(7),
    DEFINE_WAY_HANDLER(8),
    DEFINE_WAY_HANDLER(9),
    DEFINE_WAY_HANDLER(10),
    DEFINE_WAY_HANDLER(11),
    DEFINE_WAY_HANDLER(12),
    DEFINE_WAY_HANDLER(13),
    DEFINE_WAY_HANDLER(14),
    DEFINE_WAY_HANDLER(15),
    DEFINE_WAY_HANDLER(16),
    DEFINE_WAY_HANDLER(17),
    DEFINE_WAY_HANDLER(18),
    DEFINE_WAY_HANDLER(19),
    DEFINE_WAY_HANDLER(20),
    DEFINE_WAY_HANDLER(21),
    DEFINE_WAY_HANDLER(22),
    DEFINE_WAY_HANDLER(23),
    DEFINE_WAY_HANDLER(24),
    DEFINE_WAY_HANDLER(25),
    DEFINE_WAY_HANDLER(26),
    DEFINE_WAY_HANDLER(27),
    DEFINE_WAY_HANDLER(28),
    DEFINE_WAY_HANDLER(29),
    DEFINE_WAY_HANDLER(30),
    DEFINE_WAY_HANDLER(31),
    { }
};

static struct ctl_table litmus_dir_table[] = {
	{
		.procname	= "litmus",
 		.mode		= 0555,
		.child		= cache_table,
	},
	{ }
};

static struct ctl_table_header *litmus_sysctls;

static int __init litmus_sysctl_init(void)
{
	int ret = 0;
    int index;

	way_partition_min = 0x00000000;
	way_partition_max = 0x0000FFFF;
	rt_pid_min = 1;
	rt_pid_max = 10000;
	rt_cp_min = 0x0;
	rt_cp_max = 0xFFFF;

    // set
    set_partition_min = 0x00000001;
    set_partition_max = 0xffffffff;

    init_page_coloring();
	
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    litmus_setup_msr();
#endif

    // adjust entry number as online cpu numbers
    index = 7 + num_online_cpus();
#if defined(CONFIG_ARM)
    index += 4;
#endif
    cache_table[index].procname = NULL;

	printk(KERN_INFO "Registering LITMUS^RT proc sysctl.\n");
	litmus_sysctls = register_sysctl_table(litmus_dir_table);
	if (!litmus_sysctls) {
		printk(KERN_WARNING "Could not register LITMUS^RT sysctl.\n");
		ret = -EFAULT;
		goto out;
	}

out:
	return ret;
}

module_init(litmus_sysctl_init);
