#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/time.h>

#include <litmus/litmus_proc.h>
#include <litmus/sched_trace.h>
#include <litmus/cache_proc.h>

#include <asm/hardware/cache-l2x0.h>
#include <asm/cacheflush.h>


#define UNLOCK_ALL	0x00000000 /* allocation in any way */
#define LOCK_ALL        (~UNLOCK_ALL)
#define MAX_NR_WAYS	16
#define MAX_NR_COLORS	16

/*
 * unlocked_way[i] : allocation can occur in way i
 *
 * 0 = allocation can occur in the corresponding way
 * 1 = allocation cannot occur in the corresponding way
 */
u32 unlocked_way[MAX_NR_WAYS]  = {
	0xFFFFFFFE, /* way 0 unlocked */
	0xFFFFFFFD,
	0xFFFFFFFB,
	0xFFFFFFF7,
	0xFFFFFFEF, /* way 4 unlocked */
	0xFFFFFFDF,
	0xFFFFFFBF,
	0xFFFFFF7F,
	0xFFFFFEFF, /* way 8 unlocked */
	0xFFFFFDFF,
	0xFFFFFBFF,
	0xFFFFF7FF,
	0xFFFFEFFF, /* way 12 unlocked */
	0xFFFFDFFF,
	0xFFFFBFFF,
	0xFFFF7FFF,
};

u32 nr_unlocked_way[MAX_NR_WAYS+1]  = {
	0x0000FFFF, /* all ways are locked. usable = 0*/
	0x0000FFFE, /* way ~0 unlocked. usable = 1 */
	0x0000FFFC,
	0x0000FFF8,
	0x0000FFF0,
	0x0000FFE0,
	0x0000FFC0,
	0x0000FF80,
	0x0000FF00,
	0x0000FE00,
	0x0000FC00,
	0x0000F800,
	0x0000F000,
	0x0000E000,
	0x0000C000,
	0x00008000,
	0x00000000, /* way ~15 unlocked. usable = 16 */
};

u32 way_partition[4] = {
	0xfffffff0, /* cpu0 */
	0xffffff0f, /* cpu1 */
	0xfffff0ff, /* cpu2 */
	0xffff0fff, /* cpu3 */
};

u32 way_partitions[9] = {
	0xffff0003, /* cpu0 A */
	0xffff0003, /* cpu0 B */
	0xffff000C, /* cpu1 A */
	0xffff000C, /* cpu1 B */
	0xffff0030, /* cpu2 A */
	0xffff0030, /* cpu2 B */
	0xffff00C0, /* cpu3 A */
	0xffff00C0, /* cpu3 B */
	0xffffff00, /* lv C */
};

u32 prev_lockdown_d_reg[5] = {
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x000000FF, /* share with level-C */
};

u32 prev_lockdown_i_reg[5] = {
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x0000FF00,
	0x000000FF, /* share with level-C */
};

u32 prev_lbm_i_reg[8] = {
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

u32 prev_lbm_d_reg[8] = {
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

static void __iomem *cache_base;
static void __iomem *lockreg_d;
static void __iomem *lockreg_i;

static u32 cache_id;

struct mutex actlr_mutex;
struct mutex l2x0_prefetch_mutex;
struct mutex lockdown_proc;
static u32 way_partition_min;
static u32 way_partition_max;

static int zero = 0;
static int one = 1;

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

int lock_all;
int nr_lockregs;
static raw_spinlock_t cache_lock;
static raw_spinlock_t prefetch_lock;

extern void l2x0_flush_all(void);

static void print_lockdown_registers(int cpu)
{
	int i;
	for (i = 0; i < 4; i++) {
		printk("P%d Lockdown Data CPU %2d: 0x%04x\n", cpu,
				i, readl_relaxed(ld_d_reg(i)));
		printk("P%d Lockdown Inst CPU %2d: 0x%04x\n", cpu,
				i, readl_relaxed(ld_i_reg(i)));
	}
}

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

void litmus_setup_lockdown(void __iomem *base, u32 id)
{
	cache_base = base;
	cache_id = id;
	lockreg_d = cache_base + L2X0_LOCKDOWN_WAY_D_BASE;
	lockreg_i = cache_base + L2X0_LOCKDOWN_WAY_I_BASE;
    
	if (L2X0_CACHE_ID_PART_L310 == (cache_id & L2X0_CACHE_ID_PART_MASK)) {
		nr_lockregs = 8;
	} else {
		printk("Unknown cache ID!\n");
		nr_lockregs = 1;
	}
	
	mutex_init(&actlr_mutex);
	mutex_init(&l2x0_prefetch_mutex);
	mutex_init(&lockdown_proc);
	raw_spin_lock_init(&cache_lock);
	raw_spin_lock_init(&prefetch_lock);
	
	test_lockdown(NULL);
}

int way_partition_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;
	
	mutex_lock(&lockdown_proc);
	
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	
	if (write) {
		printk("Way-partition settings:\n");
		for (i = 0; i < 9; i++) {
			printk("0x%08X\n", way_partitions[i]);
		}
		for (i = 0; i < 4; i++) {
			writel_relaxed(~way_partitions[i*2], cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(~way_partitions[i*2], cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}
	}
	
	local_irq_save(flags);
	print_lockdown_registers(smp_processor_id());
	local_irq_restore(flags);
out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

int lock_all_handler(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int ret = 0, i;
	unsigned long flags;
	
	mutex_lock(&lockdown_proc);
	
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	
	if (write && lock_all == 1) {
		for (i = 0; i < nr_lockregs; i++) {
			writel_relaxed(0xFFFF, cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(0xFFFF, cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}

	}
	if (write && lock_all == 0) {
		for (i = 0; i < nr_lockregs; i++) {
			writel_relaxed(0x0, cache_base + L2X0_LOCKDOWN_WAY_D_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
			writel_relaxed(0x0, cache_base + L2X0_LOCKDOWN_WAY_I_BASE +
				       i * L2X0_LOCKDOWN_STRIDE);
		}
	}
	printk("LOCK_ALL HANDLER\n");
	local_irq_save(flags);
	print_lockdown_registers(smp_processor_id());
	local_irq_restore(flags);
out:
	mutex_unlock(&lockdown_proc);
	return ret;
}

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

int setup_flusher_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
		
static struct ctl_table cache_table[] =
{
	{
		.procname	= "C0_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[0],
		.maxlen		= sizeof(way_partitions[0]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},	
	{
		.procname	= "C0_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[1],
		.maxlen		= sizeof(way_partitions[1]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},	
	{
		.procname	= "C1_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[2],
		.maxlen		= sizeof(way_partitions[2]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C1_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[3],
		.maxlen		= sizeof(way_partitions[3]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C2_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[4],
		.maxlen		= sizeof(way_partitions[4]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C2_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[5],
		.maxlen		= sizeof(way_partitions[5]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C3_LA_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[6],
		.maxlen		= sizeof(way_partitions[6]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},
	{
		.procname	= "C3_LB_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[7],
		.maxlen		= sizeof(way_partitions[7]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},	
	{
		.procname	= "Call_LC_way",
		.mode		= 0666,
		.proc_handler	= way_partition_handler,
		.data		= &way_partitions[8],
		.maxlen		= sizeof(way_partitions[8]),
		.extra1		= &way_partition_min,
		.extra2		= &way_partition_max,
	},		
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

	printk(KERN_INFO "Registering LITMUS^RT proc sysctl.\n");
	litmus_sysctls = register_sysctl_table(litmus_dir_table);
	if (!litmus_sysctls) {
		printk(KERN_WARNING "Could not register LITMUS^RT sysctl.\n");
		ret = -EFAULT;
		goto out;
	}

	way_partition_min = 0x00000000;
	way_partition_max = 0x0000FFFF;
	
out:
	return ret;
}

module_init(litmus_sysctl_init);
