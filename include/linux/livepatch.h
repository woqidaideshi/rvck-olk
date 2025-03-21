/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - Kernel Live Patching Core
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2014 SUSE
 */

#ifndef _LINUX_LIVEPATCH_H_
#define _LINUX_LIVEPATCH_H_

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/livepatch_sched.h>

#if IS_ENABLED(CONFIG_LIVEPATCH)

#include <asm/livepatch.h>

/* task patch states */
#define KLP_UNDEFINED	-1
#define KLP_UNPATCHED	 0
#define KLP_PATCHED	 1

#define KLP_NORMAL_FORCE	0
#define KLP_ENFORCEMENT		1
#define KLP_STACK_OPTIMIZE	2

/**
 * struct klp_func - function structure for live patching
 * @old_name:	name of the function to be patched
 * @new_func:	pointer to the patched function code
 * @old_sympos: a hint indicating which symbol position the old function
 *		can be found (optional)
 * @old_func:	pointer to the function being patched
 * @kobj:	kobject for sysfs resources
 * @node:	list node for klp_object func_list
 * @stack_node:	list node for klp_ops func_stack list
 * @old_size:	size of the old function
 * @new_size:	size of the new function
 * @nop:        temporary patch to use the original code again; dyn. allocated
 * @patched:	the func has been added to the klp_ops list
 * @transition:	the func is currently being applied or reverted
 *
 * The patched and transition variables define the func's patching state.  When
 * patching, a func is always in one of the following states:
 *
 *   patched=0 transition=0: unpatched
 *   patched=0 transition=1: unpatched, temporary starting state
 *   patched=1 transition=1: patched, may be visible to some tasks
 *   patched=1 transition=0: patched, visible to all tasks
 *
 * And when unpatching, it goes in the reverse order:
 *
 *   patched=1 transition=0: patched, visible to all tasks
 *   patched=1 transition=1: patched, may be visible to some tasks
 *   patched=0 transition=1: unpatched, temporary ending state
 *   patched=0 transition=0: unpatched
 */
struct klp_func {
	/* external */
	const char *old_name;
	void *new_func;
	/*
	 * The old_sympos field is optional and can be used to resolve
	 * duplicate symbol names in livepatch objects. If this field is zero,
	 * it is expected the symbol is unique, otherwise patching fails. If
	 * this value is greater than zero then that occurrence of the symbol
	 * in kallsyms for the given object is used.
	 */
	unsigned long old_sympos;
	int force; /* Only used in the solution without ftrace */

	/* internal */
	void *old_func;
	struct kobject kobj;
	struct list_head node;
	struct list_head stack_node;
	unsigned long old_size, new_size;
	bool nop; /* Not used in the solution without ftrace */
	bool patched;
#ifdef CONFIG_LIVEPATCH_FTRACE
	bool transition;
#endif
#if defined(CONFIG_LIVEPATCH_WO_FTRACE) && defined(CONFIG_PPC64)
	struct module *old_mod;
	struct module *this_mod;
	struct func_desc new_func_descr;
#endif
	void *func_node; /* Only used in the solution without ftrace */
};

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
struct klp_hook {
	void (*hook)(void);
};
#endif /* CONFIG_LIVEPATCH_WO_FTRACE */

struct klp_object;

/**
 * struct klp_callbacks - pre/post live-(un)patch callback structure
 * @pre_patch:		executed before code patching
 * @post_patch:		executed after code patching
 * @pre_unpatch:	executed before code unpatching
 * @post_unpatch:	executed after code unpatching
 * @post_unpatch_enabled:	flag indicating if post-unpatch callback
 * 				should run
 *
 * All callbacks are optional.  Only the pre-patch callback, if provided,
 * will be unconditionally executed.  If the parent klp_object fails to
 * patch for any reason, including a non-zero error status returned from
 * the pre-patch callback, no further callbacks will be executed.
 */
struct klp_callbacks {
	int (*pre_patch)(struct klp_object *obj);
	void (*post_patch)(struct klp_object *obj);
	void (*pre_unpatch)(struct klp_object *obj);
	void (*post_unpatch)(struct klp_object *obj);
	bool post_unpatch_enabled;
};

/**
 * struct klp_object - kernel object structure for live patching
 * @name:	module name (or NULL for vmlinux)
 * @funcs:	function entries for functions to be patched in the object
 * @callbacks:	functions to be executed pre/post (un)patching
 * @kobj:	kobject for sysfs resources
 * @func_list:	dynamic list of the function entries
 * @node:	list node for klp_patch obj_list
 * @mod:	kernel module associated with the patched object
 *		(NULL for vmlinux)
 * @dynamic:    temporary object for nop functions; dynamically allocated
 * @patched:	the object's funcs have been added to the klp_ops list
 */
struct klp_object {
	/* external */
	const char *name;
	struct klp_func *funcs;
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	struct klp_hook *hooks_load;
	struct klp_hook *hooks_unload;
#endif
	struct klp_callbacks callbacks; /* Not used in the solution without ftrace */

	/* internal */
	struct kobject kobj;
	struct list_head func_list;
	struct list_head node;
	struct module *mod;
	bool dynamic; /* Not used in the solution without ftrace */
	bool patched;
};

/**
 * struct klp_state - state of the system modified by the livepatch
 * @id:		system state identifier (non-zero)
 * @version:	version of the change
 * @data:	custom data
 */
struct klp_state {
	unsigned long id;
	unsigned int version;
	void *data;
};

/**
 * struct klp_patch - patch structure for live patching
 * @mod:	reference to the live patch module
 * @objs:	object entries for kernel objects to be patched
 * @states:	system states that can get modified
 * @replace:	replace all actively used patches
 * @list:	list node for global list of actively used patches
 * @kobj:	kobject for sysfs resources
 * @obj_list:	dynamic list of the object entries
 * @enabled:	the patch is enabled (but operation may be incomplete)
 * @forced:	was involved in a forced transition
 * @free_work:	patch cleanup from workqueue-context
 * @finish:	for waiting till it is safe to remove the patch module
 */
struct klp_patch {
	/* external */
	struct module *mod;
	struct klp_object *objs;
	struct klp_state *states; /* Not used in the solution without ftrace */
	bool replace; /* Not supported in the solution without ftrace */

	/* internal */
	struct list_head list;
	struct kobject kobj;
	struct list_head obj_list;
	bool enabled;
	bool forced; /* Not used in the solution without ftrace */
	struct work_struct free_work; /* Not used in the solution without ftrace */
	struct completion finish;
};

#define klp_for_each_object_static(patch, obj) \
	for (obj = patch->objs; obj->funcs || obj->name; obj++)

#define klp_for_each_object_safe(patch, obj, tmp_obj)		\
	list_for_each_entry_safe(obj, tmp_obj, &patch->obj_list, node)

#define klp_for_each_object(patch, obj)	\
	list_for_each_entry(obj, &patch->obj_list, node)

#define klp_for_each_func_static(obj, func) \
	for (func = obj->funcs; \
	     func->old_name || func->new_func || func->old_sympos; \
	     func++)

#define klp_for_each_func_safe(obj, func, tmp_func)			\
	list_for_each_entry_safe(func, tmp_func, &obj->func_list, node)

#define klp_for_each_func(obj, func)	\
	list_for_each_entry(func, &obj->func_list, node)

#ifdef CONFIG_LIVEPATCH_FTRACE
int klp_enable_patch(struct klp_patch *);

/* Called from the module loader during module coming/going states */
int klp_module_coming(struct module *mod);
void klp_module_going(struct module *mod);

void klp_copy_process(struct task_struct *child);
void klp_update_patch_state(struct task_struct *task);

static inline bool klp_patch_pending(struct task_struct *task)
{
	return test_tsk_thread_flag(task, TIF_PATCH_PENDING);
}

static inline bool klp_have_reliable_stack(void)
{
	return IS_ENABLED(CONFIG_STACKTRACE) &&
	       IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE);
}

typedef int (*klp_shadow_ctor_t)(void *obj,
				 void *shadow_data,
				 void *ctor_data);
typedef void (*klp_shadow_dtor_t)(void *obj, void *shadow_data);

void *klp_shadow_get(void *obj, unsigned long id);
void *klp_shadow_alloc(void *obj, unsigned long id,
		       size_t size, gfp_t gfp_flags,
		       klp_shadow_ctor_t ctor, void *ctor_data);
void *klp_shadow_get_or_alloc(void *obj, unsigned long id,
			      size_t size, gfp_t gfp_flags,
			      klp_shadow_ctor_t ctor, void *ctor_data);
void klp_shadow_free(void *obj, unsigned long id, klp_shadow_dtor_t dtor);
void klp_shadow_free_all(unsigned long id, klp_shadow_dtor_t dtor);

struct klp_state *klp_get_state(struct klp_patch *patch, unsigned long id);
struct klp_state *klp_get_prev_state(unsigned long id);

#else /* !CONFIG_LIVEPATCH_FTRACE */

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	void *old_func;
	struct arch_klp_data arch_data;
	/*
	 * Used in breakpoint exception handling functions.
	 * If 'brk_func' is NULL, no breakpoint is inserted into the entry of
	 * the old function.
	 * If it is not NULL, the value is the new function that will jump to
	 * when the breakpoint exception is triggered.
	 */
	void *brk_func;
};

void *klp_get_brk_func(void *addr);

static inline
int klp_compare_address(unsigned long pc, unsigned long func_addr,
			const char *func_name, unsigned long check_size)
{
	if (pc >= func_addr && pc < func_addr + check_size) {
		pr_warn("func %s is in use!\n", func_name);
		/* Return -EAGAIN for next retry */
		return -EAGAIN;
	}
	return 0;
}

void arch_klp_init(void);
int klp_module_delete_safety_check(struct module *mod);

typedef int (*klp_add_func_t)(struct list_head *func_list,
			       unsigned long func_addr, unsigned long func_size,
			       const char *func_name, int force);

struct walk_stackframe_args {
	void *data;
	int ret;
	bool (*check_func)(void *data, int *ret, unsigned long pc);
};

#ifndef klp_smp_isb
#define klp_smp_isb()
#endif

#define KLP_MIGRATION_NAME_PREFIX	"migration/"
static inline bool klp_is_migration_thread(const char *task_name)
{
	/*
	 * current on other CPU
	 * we call this in stop_machine, so the current
	 * of each CPUs is migration, just compare the
	 * task_comm here, because we can't get the
	 * cpu_curr(task_cpu(t))). This assumes that no
	 * other thread will pretend to be a stopper via
	 * task_comm.
	 */
	return !strncmp(task_name, KLP_MIGRATION_NAME_PREFIX,
			sizeof(KLP_MIGRATION_NAME_PREFIX) - 1);
}

/*
 * When the thread become zombie or dead, it's stack memory may have
 * been freed, we can not check calltrace for it.
 */
static inline bool klp_is_thread_dead(const struct task_struct *t)
{
	int exit_state = READ_ONCE(t->exit_state);

	return ((exit_state & EXIT_ZOMBIE) == EXIT_ZOMBIE) ||
		((exit_state & EXIT_DEAD) == EXIT_DEAD);
}

int klp_register_patch(struct klp_patch *patch);
int klp_unregister_patch(struct klp_patch *patch);
static inline int klp_module_coming(struct module *mod) { return 0; }
static inline void klp_module_going(struct module *mod) {}
static inline bool klp_patch_pending(struct task_struct *task) { return false; }
static inline void klp_update_patch_state(struct task_struct *task) {}
static inline void klp_copy_process(struct task_struct *child) {}
static inline bool klp_have_reliable_stack(void) { return true; }
extern void module_enable_ro(const struct module *mod, bool after_init);
extern void module_disable_ro(const struct module *mod);

#endif /* CONFIG_LIVEPATCH_FTRACE */

int klp_apply_section_relocs(struct module *pmod, Elf_Shdr *sechdrs,
			     const char *shstrtab, const char *strtab,
			     unsigned int symindex, unsigned int secindex,
			     const char *objname);

#else /* !CONFIG_LIVEPATCH */

static inline int klp_module_coming(struct module *mod) { return 0; }
static inline void klp_module_going(struct module *mod) {}
static inline bool klp_patch_pending(struct task_struct *task) { return false; }
static inline void klp_update_patch_state(struct task_struct *task) {}
static inline void klp_copy_process(struct task_struct *child) {}

static inline
int klp_apply_section_relocs(struct module *pmod, Elf_Shdr *sechdrs,
			     const char *shstrtab, const char *strtab,
			     unsigned int symindex, unsigned int secindex,
			     const char *objname)
{
	return 0;
}

#endif /* CONFIG_LIVEPATCH */

#ifdef CONFIG_LIVEPATCH_ISOLATE_KPROBE
void klp_lock(void);
void klp_unlock(void);
int klp_check_patched(unsigned long addr);
#else /* !CONFIG_LIVEPATCH_ISOLATE_KPROBE */
static inline void klp_lock(void) { }
static inline void klp_unlock(void) { }
static inline int klp_check_patched(unsigned long addr)
{
	return 0;
}
#endif /* CONFIG_LIVEPATCH_ISOLATE_KPROBE */

#endif /* _LINUX_LIVEPATCH_H_ */
