/* SPDX-License-Identifier: GPL-2.0 */
/* thread_info.h: common low-level thread information accessors
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds
 */

#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/bug.h>
#include <linux/restart_block.h>
#include <linux/errno.h>
#include <linux/thread_bits.h>

#include <linux/bitops.h>

#ifdef CONFIG_GENERIC_ENTRY
enum syscall_work_bit {
	SYSCALL_WORK_BIT_SECCOMP,
	SYSCALL_WORK_BIT_SYSCALL_TRACEPOINT,
	SYSCALL_WORK_BIT_SYSCALL_TRACE,
	SYSCALL_WORK_BIT_SYSCALL_EMU,
	SYSCALL_WORK_BIT_SYSCALL_AUDIT,
	SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH,
	SYSCALL_WORK_BIT_SYSCALL_EXIT_TRAP,
};

#define SYSCALL_WORK_SECCOMP		BIT(SYSCALL_WORK_BIT_SECCOMP)
#define SYSCALL_WORK_SYSCALL_TRACEPOINT	BIT(SYSCALL_WORK_BIT_SYSCALL_TRACEPOINT)
#define SYSCALL_WORK_SYSCALL_TRACE	BIT(SYSCALL_WORK_BIT_SYSCALL_TRACE)
#define SYSCALL_WORK_SYSCALL_EMU	BIT(SYSCALL_WORK_BIT_SYSCALL_EMU)
#define SYSCALL_WORK_SYSCALL_AUDIT	BIT(SYSCALL_WORK_BIT_SYSCALL_AUDIT)
#define SYSCALL_WORK_SYSCALL_USER_DISPATCH BIT(SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH)
#define SYSCALL_WORK_SYSCALL_EXIT_TRAP	BIT(SYSCALL_WORK_BIT_SYSCALL_EXIT_TRAP)
#endif

#include <asm/thread_info.h>

#ifdef __KERNEL__

#ifndef arch_set_restart_data
#define arch_set_restart_data(restart) do { } while (0)
#endif

static inline long set_restart_fn(struct restart_block *restart,
					long (*fn)(struct restart_block *))
{
	restart->fn = fn;
	arch_set_restart_data(restart);
	return -ERESTART_RESTARTBLOCK;
}

#ifndef THREAD_ALIGN
#define THREAD_ALIGN	THREAD_SIZE
#endif

#define THREADINFO_GFP		(GFP_KERNEL_ACCOUNT | __GFP_ZERO)

/*
 * This may be used in noinstr code, and needs to be __always_inline to prevent
 * inadvertent instrumentation.
 */
static __always_inline unsigned long read_ti_thread_flags(struct thread_info *ti)
{
	return READ_ONCE(ti->flags);
}

#define read_thread_flags() \
	read_ti_thread_flags(current_thread_info())

#define read_task_thread_flags(t) \
	read_ti_thread_flags(task_thread_info(t))

#ifdef CONFIG_GENERIC_ENTRY
#define set_syscall_work(fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define test_syscall_work(fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define clear_syscall_work(fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)

#define set_task_syscall_work(t, fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define test_task_syscall_work(t, fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define clear_task_syscall_work(t, fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)

#else /* CONFIG_GENERIC_ENTRY */

#define set_syscall_work(fl)						\
	set_ti_thread_flag(current_thread_info(), TIF_##fl)
#define test_syscall_work(fl) \
	test_ti_thread_flag(current_thread_info(), TIF_##fl)
#define clear_syscall_work(fl) \
	clear_ti_thread_flag(current_thread_info(), TIF_##fl)

#define set_task_syscall_work(t, fl) \
	set_ti_thread_flag(task_thread_info(t), TIF_##fl)
#define test_task_syscall_work(t, fl) \
	test_ti_thread_flag(task_thread_info(t), TIF_##fl)
#define clear_task_syscall_work(t, fl) \
	clear_ti_thread_flag(task_thread_info(t), TIF_##fl)
#endif /* !CONFIG_GENERIC_ENTRY */

#ifdef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H

static __always_inline bool tif_need_resched(void)
{
	return arch_test_bit(TIF_NEED_RESCHED,
			     (unsigned long *)(&current_thread_info()->flags));
}

#else

static __always_inline bool tif_need_resched(void)
{
	return test_bit(TIF_NEED_RESCHED,
			(unsigned long *)(&current_thread_info()->flags));
}

#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */

#ifndef CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES
static inline int arch_within_stack_frames(const void * const stack,
					   const void * const stackend,
					   const void *obj, unsigned long len)
{
	return 0;
}
#endif

#ifdef CONFIG_HARDENED_USERCOPY
extern void __check_object_size(const void *ptr, unsigned long n,
					bool to_user);

static __always_inline void check_object_size(const void *ptr, unsigned long n,
					      bool to_user)
{
	if (!__builtin_constant_p(n))
		__check_object_size(ptr, n, to_user);
}
#else
static inline void check_object_size(const void *ptr, unsigned long n,
				     bool to_user)
{ }
#endif /* CONFIG_HARDENED_USERCOPY */

extern void __compiletime_error("copy source size is too small")
__bad_copy_from(void);
extern void __compiletime_error("copy destination size is too small")
__bad_copy_to(void);

void __copy_overflow(int size, unsigned long count);

static inline void copy_overflow(int size, unsigned long count)
{
	if (IS_ENABLED(CONFIG_BUG))
		__copy_overflow(size, count);
}

static __always_inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	int sz = __builtin_object_size(addr, 0);
	if (unlikely(sz >= 0 && sz < bytes)) {
		if (!__builtin_constant_p(bytes))
			copy_overflow(sz, bytes);
		else if (is_source)
			__bad_copy_from();
		else
			__bad_copy_to();
		return false;
	}
	if (WARN_ON_ONCE(bytes > INT_MAX))
		return false;
	check_object_size(addr, bytes, is_source);
	return true;
}

#ifndef arch_setup_new_exec
static inline void arch_setup_new_exec(void) { }
#endif

void arch_task_cache_init(void); /* for CONFIG_SH */
void arch_release_task_struct(struct task_struct *tsk);
int arch_dup_task_struct(struct task_struct *dst,
				struct task_struct *src);

#endif	/* __KERNEL__ */

#endif /* _LINUX_THREAD_INFO_H */
