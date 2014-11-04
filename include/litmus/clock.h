#ifndef _LITMUS_CLOCK_H_
#define _LITMUS_CLOCK_H_

#if defined(CONFIG_EXYNOS_MCT)

/*
 * Only used if we are using the EXYNOS MCT clock.
 */

#include <linux/clocksource.h>
extern struct clocksource mct_frc;

static inline cycles_t mct_frc_read(void)
{
	cycle_t cycles = mct_frc.read(&mct_frc);
	return cycles;
}

static inline s64 litmus_cycles_to_ns(cycles_t cycles)
{
	return clocksource_cyc2ns(cycles, mct_frc.mult, mct_frc.shift);
}

#define litmus_get_cycles mct_frc_read

#elif defined(CONFIG_CPU_V7) && !defined(CONFIG_HW_PERF_EVENTS)

#include <asm/timex.h>

static inline cycles_t v7_get_cycles (void)
{
	u32 value;
        /* read CCNT register */
        asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(value));
	return value;
}

#define litmus_get_cycles v7_get_cycles

#else
#include <asm/timex.h>

#define litmus_get_cycles get_cycles

#endif

#endif

