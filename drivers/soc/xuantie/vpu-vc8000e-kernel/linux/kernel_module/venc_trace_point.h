/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM venc_trace_point

#if !defined(_TRACE_VENC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VENC_H

#include <linux/sched/numa_balancing.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

TRACE_EVENT(venc_interrupt,

       TP_PROTO(unsigned int complete_cmd, unsigned int irq_status, unsigned int processed_vcmd_num),

       TP_ARGS(complete_cmd, irq_status,processed_vcmd_num),

       TP_STRUCT__entry(
               __field(        unsigned int,   complete_cmd )
               __field(        unsigned int,   irq_status)
               __field(        unsigned int,   processed_vcmd_num)
       ),

       TP_fast_assign(
               __entry->complete_cmd = complete_cmd;
               __entry->irq_status = irq_status;
               __entry->processed_vcmd_num = processed_vcmd_num;
       ),

       TP_printk("venc irq type complete_cmd %u irq status =%x processed_vcmd_num %d ", __entry->complete_cmd, __entry->irq_status,__entry->processed_vcmd_num)
);

#endif /* _TRACE_VENC_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .

/* This is needed because the name of this file doesn't match TRACE_SYSTEM. */
#define TRACE_INCLUDE_FILE venc_trace_point

/* This part must be outside protection */
#include <trace/define_trace.h>
