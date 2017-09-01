/**
 * Test VCPUOP_get_rt_info hypercall, which
 * get the current remaining budget of a specified vcpu
 */

/* Kernel Programming */
#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <xen/interface/vcpu.h>
#include <xen/xen-ops.h>

int init_module(void)
{
    struct vcpu_rt_info rtinfo;

    printk("This is test module for VCPUOP_get_rt_info hypercall.\n");
    memset(&rtinfo, 0, sizeof(rtinfo));

    xen_get_rt_info(0, &rtinfo);
    
    printk("---rtinfo---\n");
    printk("period=%ld budget=%ld cur_budget=%ld\n",
            rtinfo.period, rtinfo.budget, rtinfo.cur_budget);
    printk("------------\n");

    return 0;
}

void cleanup_module(void)
{
    printk(KERN_ALERT "Test done.\n");
}
