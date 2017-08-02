
/*
 * smp_call_function_single() is not exported below 2.6.20.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

/* The 'nonatomic' argument was removed in 2.6.27. */

#undef smp_call_function_single

#include <linux/smp.h>

#ifdef CONFIG_SMP
int kvm_smp_call_function_single(int cpu, void (*func)(void *info),
				 void *info, int wait)
{
	return smp_call_function_single(cpu, func, info, 0, wait);
}
#else /* !CONFIG_SMP */
int kvm_smp_call_function_single(int cpu, void (*func)(void *info),
				 void *info, int wait)
{
	WARN_ON(cpu != 0);
	local_irq_disable();
	func(info);
	local_irq_enable();
	return 0;

}
#endif /* !CONFIG_SMP */
EXPORT_SYMBOL_GPL(kvm_smp_call_function_single);

#define smp_call_function_single kvm_smp_call_function_single

#endif

/* div64_u64 is fairly new */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

#ifndef CONFIG_64BIT

/* 64bit divisor, dividend and result. dynamic precision */
uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	uint32_t high, d;

	high = divisor >> 32;
	if (high) {
		unsigned int shift = fls(high);

		d = divisor >> shift;
		dividend >>= shift;
	} else
		d = divisor;

	do_div(dividend, d);

	return dividend;
}

#endif

#endif

/*
 * smp_call_function_mask() is not defined/exported below 2.6.24 on all
 * targets and below 2.6.26 on x86-64
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) || \
    (defined CONFIG_X86_64 && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))

#include <linux/smp.h>

struct kvm_call_data_struct {
	void (*func) (void *info);
	void *info;
	atomic_t started;
	atomic_t finished;
	int wait;
};

static void kvm_ack_smp_call(void *_data)
{
	struct kvm_call_data_struct *data = _data;
	/* if wait == 0, data can be out of scope
	 * after atomic_inc(info->started)
	 */
	void (*func) (void *info) = data->func;
	void *info = data->info;
	int wait = data->wait;

	smp_mb();
	atomic_inc(&data->started);
	(*func)(info);
	if (wait) {
		smp_mb();
		atomic_inc(&data->finished);
	}
}

int kvm_smp_call_function_mask(cpumask_t mask,
			       void (*func) (void *info), void *info, int wait)
{
#ifdef CONFIG_SMP
	struct kvm_call_data_struct data;
	cpumask_t allbutself;
	int cpus;
	int cpu;
	int me;

	me = get_cpu();
	WARN_ON(irqs_disabled());
	allbutself = cpu_online_map;
	cpu_clear(me, allbutself);

	cpus_and(mask, mask, allbutself);
	cpus = cpus_weight(mask);

	if (!cpus)
		goto out;

	data.func = func;
	data.info = info;
	atomic_set(&data.started, 0);
	data.wait = wait;
	if (wait)
		atomic_set(&data.finished, 0);

	for (cpu = first_cpu(mask); cpu != NR_CPUS; cpu = next_cpu(cpu, mask))
		smp_call_function_single(cpu, kvm_ack_smp_call, &data, 0);

	while (atomic_read(&data.started) != cpus) {
		cpu_relax();
		barrier();
	}

	if (!wait)
		goto out;

	while (atomic_read(&data.finished) != cpus) {
		cpu_relax();
		barrier();
	}
out:
	put_cpu();
#endif /* CONFIG_SMP */
	return 0;
}

#include <linux/workqueue.h>

static void vcpu_kick_intr(void *info)
{
}

struct kvm_kick {
	int cpu;
	struct work_struct work;
};

static void kvm_do_smp_call_function(struct work_struct *work)
{
	int me = get_cpu();
	struct kvm_kick *kvm_kick = container_of(work, struct kvm_kick, work);

	if (kvm_kick->cpu != me)
		smp_call_function_single(kvm_kick->cpu, vcpu_kick_intr,
					 NULL, 0);
	kfree(kvm_kick);
	put_cpu();
}

void kvm_queue_smp_call_function(int cpu)
{
	struct kvm_kick *kvm_kick = kmalloc(sizeof(struct kvm_kick), GFP_ATOMIC);

	INIT_WORK(&kvm_kick->work, kvm_do_smp_call_function);

	schedule_work(&kvm_kick->work);
}

void kvm_smp_send_reschedule(int cpu)
{
	if (irqs_disabled()) {
		kvm_queue_smp_call_function(cpu);
		return;
	}
	smp_call_function_single(cpu, vcpu_kick_intr, NULL, 0);
}
#endif

#include <linux/intel-iommu.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

int intel_iommu_found()
{
	return 0;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

static enum hrtimer_restart kvm_hrtimer_wakeup(struct hrtimer *timer)
{
	struct hrtimer_sleeper *t =
		container_of(timer, struct hrtimer_sleeper, timer);
	struct task_struct *task = t->task;

	t->task = NULL;
	if (task)
		wake_up_process(task);

	return HRTIMER_NORESTART;
}

int schedule_hrtimeout(ktime_t *expires, const enum hrtimer_mode mode)
{
	struct hrtimer_sleeper t;

	/*
	 * Optimize when a zero timeout value is given. It does not
	 * matter whether this is an absolute or a relative time.
	 */
	if (expires && !expires->tv64) {
		__set_current_state(TASK_RUNNING);
		return 0;
	}

	/*
	 * A NULL parameter means "inifinte"
	 */
	if (!expires) {
		schedule();
		__set_current_state(TASK_RUNNING);
		return -EINTR;
	}

	hrtimer_init(&t.timer, CLOCK_MONOTONIC, mode);
	t.timer.expires = *expires;

	t.timer.function = kvm_hrtimer_wakeup;
	t.task = current;

	hrtimer_start(&t.timer, t.timer.expires, mode);
	if (!hrtimer_active(&t.timer))
		t.task = NULL;

	if (likely(t.task))
		schedule();

	hrtimer_cancel(&t.timer);

	__set_current_state(TASK_RUNNING);

	return !t.task ? 0 : -EINTR;
}

#endif

#ifndef CONFIG_USER_RETURN_NOTIFIER

DEFINE_PER_CPU(struct kvm_user_return_notifier *, kvm_urn) = NULL;

#endif /* CONFIG_USER_RETURN_NOTIFIER */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#include <linux/sysdev.h>
#include <linux/syscore_ops.h>

int kvm_suspend(void);
void kvm_resume(void);

static int kvm_compat_suspend(struct sys_device *dev, pm_message_t state)
{
	kvm_suspend();
	return 0;
}

static struct sysdev_class kvm_sysdev_class = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	.name = "kvm",
#else
	set_kset_name("kvm"),
#endif
	.suspend = kvm_compat_suspend,
	.resume = (int (*)(struct sys_device *))kvm_resume,
};

static struct sys_device kvm_sysdev = {
	.id = 0,
	.cls = &kvm_sysdev_class,
};

void register_syscore_ops(struct syscore_ops *ops)
{
	int r;

	r = sysdev_class_register(&kvm_sysdev_class);
	BUG_ON(r);

	r = sysdev_register(&kvm_sysdev);
	BUG_ON(r);
}
EXPORT_SYMBOL_GPL(register_syscore_ops);

void unregister_syscore_ops(struct syscore_ops *ops)
{
	sysdev_unregister(&kvm_sysdev);
	sysdev_class_unregister(&kvm_sysdev_class);
}
EXPORT_SYMBOL_GPL(unregister_syscore_ops);

#endif /* < 2.6.39 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
void *bsearch(const void *key, const void *base, size_t num, size_t size,
	      int (*cmp)(const void *key, const void *elt))
{
	size_t start = 0, end = num;
	int result;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = cmp(key, base + mid * size);
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)base + mid * size;
	}

	return NULL;
}
EXPORT_SYMBOL(bsearch);
#endif /* < 3.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
u64 ktime_get_boot_ns(void)
{
	struct timespec ts;

	ktime_get_ts(&ts);
	kvm_monotonic_to_bootbased(&ts);
	return timespec_to_ns(&ts);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/timekeeper_internal.h>

u64 kvm_get_boot_base_ns(struct timekeeper *tk)
{
	struct timespec ts = tk->wall_to_monotonic;

	kvm_monotonic_to_bootbased(&ts);
	return timespec_to_ns(&ts) + tk->xtime_sec * (u64)NSEC_PER_SEC;
}
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,3)
void *get_xsave_addr(struct xsave_struct *xsave, int feature)
{
	int index = fls64(feature) - 1;
	u32 size, offset, ecx, edx;

	cpuid_count(0xd, index, &size, &offset, &ecx, &edx);
	return (u8 *)xsave + offset;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
bool single_task_running(void)
{
	/* Not exactly the same... */
	return !need_resched();
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
/* Instead of backporting everything, just include the code from 3.19's
 * kvm_get_user_page_io, which was generalized into __get_user_pages_unlocked.
 */
static long kvm_get_user_pages_locked(struct task_struct *tsk, struct mm_struct *mm,
	 			      unsigned long addr, int nr_pages, struct page **pagep,
				      struct vm_area_struct **vmas, int *locked,
				      bool notify_drop, unsigned int flags)
{
	int npages;
	flags |= (pagep ? FOLL_GET : 0);

	BUG_ON(nr_pages != 1);

	/*
	 * If retrying the fault, we get here *not* having allowed the filemap
	 * to wait on the page lock. We should now allow waiting on the IO with
	 * the mmap semaphore released.
	 */
	npages = __get_user_pages(tsk, mm, addr, nr_pages, flags, pagep, vmas,
				  locked);
	if (!*locked) {
		VM_BUG_ON(npages);

		if (!pagep)
			return 0;

		/*
		 * The previous call has now waited on the IO. Now we can
		 * retry and complete. Pass TRIED to ensure we do not re
		 * schedule async IO (see e.g. filemap_fault).
		 */
		down_read(&mm->mmap_sem);
		*locked = 1;
		npages = __get_user_pages(tsk, mm, addr, nr_pages, flags | FOLL_TRIED,
					  pagep, vmas, NULL);
		if (notify_drop) {
			/*
			 * We must let the caller know we temporarily dropped the lock
			 * and so the critical section protected by it was lost.
			 */
			up_read(&mm->mmap_sem);
			*locked = 0;
		}
	}
	return npages;
}
#else
#define kvm_get_user_pages_locked __get_user_pages_unlocked
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,9,0)
long kvm_get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
			       unsigned long start, unsigned long nr_pages,
			       unsigned int gup_flags, struct page **pages,
			       struct vm_area_struct **vmas, int *locked)
{
	if (*locked) {
		up_read(&mm->mmap_sem);
		*locked = 0;
	}

	return kvm_get_user_pages_locked(tsk, mm, start, nr_pages, pages,
					 gup_flags | FOLL_TOUCH | FOLL_REMOTE);
}

long kvm_get_user_pages_unlocked(unsigned long addr, unsigned long nr_pages,
				 struct page **pagep, unsigned int flags)
{
	long ret;

	ret = kvm_get_user_pages_locked(current, current->mm, addr, nr_pages,
					pagep,
					flags | FOLL_TOUCH);
	return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
long kvm_get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
			       unsigned long start, unsigned long nr_pages,
			       unsigned int gup_flags, struct page **pages,
			       struct vm_area_struct **vmas, int *locked)
{
	if (*locked) {
		up_read(&mm->mmap_sem);
		*locked = 0;
	}

	return kvm_get_user_pages_locked(tsk, mm, start, nr_pages, 1, 0,
					 pages,
					 gup_flags | FOLL_TOUCH | FOLL_REMOTE);
}

long kvm_get_user_pages_unlocked(unsigned long addr, unsigned long nr_pages,
				 struct page **pagep, unsigned int flags)
{
	long ret;

	ret = kvm_get_user_pages_locked(current, current->mm, addr, nr_pages,
					1, 0, pagep,
					flags | FOLL_TOUCH);
	return ret;
}
#endif


#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
#include <linux/irqbypass.h>

int irq_bypass_register_consumer(struct irq_bypass_consumer *c)
{
	return 0;
}

void irq_bypass_unregister_consumer(struct irq_bypass_consumer *c)
{
}

void task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st)
{
	*ut = p->utime;
	*st = p->stime;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
#ifndef VM_FAULT_SIGSEGV
#define VM_FAULT_SIGSEGV 0
#endif

static inline
bool vma_permits_fault(struct vm_area_struct *vma, unsigned int fault_flags)
{
	bool write   = !!(fault_flags & FAULT_FLAG_WRITE);
	vm_flags_t vm_flags = write ? VM_WRITE : VM_READ;

	if (!(vm_flags & vma->vm_flags))
		return false;

	/* arch_vma_access_permitted check removed---assuming that
	 * pkeys are not in use.
	 */
	return true;
}

int kvm_fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm,
			 unsigned long address, unsigned int flags,
			 bool *unlocked)
{
	struct vm_area_struct *vma;
	int ret, major = 0;
	unsigned int fault_flags = 0;

	VM_WARN_ON_ONCE(flags & ~(FOLL_WRITE|FOLL_NOWAIT|
				  FOLL_TRIED|FOLL_HWPOISON));

	if (flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (unlocked)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	if (flags & FOLL_NOWAIT) {
		VM_WARN_ON_ONCE(unlocked);
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	}
	if (flags & FOLL_TRIED) {
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

retry:
	vma = find_extend_vma(mm, address);

	if (!vma || address < vma->vm_start)
		return -EFAULT;

	if (!vma_permits_fault(vma, fault_flags))
		return -EFAULT;

	ret = handle_mm_fault(mm, vma, address, fault_flags);
	major |= ret & VM_FAULT_MAJOR;
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return flags & FOLL_HWPOISON ? -EHWPOISON : -EFAULT;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}

	if (ret & VM_FAULT_RETRY) {
		if ((fault_flags & FAULT_FLAG_RETRY_NOWAIT))
			return -EBUSY;

		down_read(&mm->mmap_sem);
		if (!(fault_flags & FAULT_FLAG_TRIED)) {
			*unlocked = true;
			fault_flags &= ~FAULT_FLAG_ALLOW_RETRY;
			fault_flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	if (tsk) {
		if (major)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
static int (*kvm_cpu_notifier_startup[2])(unsigned int cpu);
static int (*kvm_cpu_notifier_teardown[2])(unsigned int cpu);

static int kvm_cpu_hotplug(struct notifier_block *notifier, unsigned long val,
			   void *v)
{
	unsigned int cpu = raw_smp_processor_id();
	val &= ~CPU_TASKS_FROZEN;
	switch (val) {
	case CPU_DYING:
		kvm_cpu_notifier_startup[CPUHP_AP_KVM_STARTING](cpu);
		break;
	case CPU_STARTING:
		kvm_cpu_notifier_teardown[CPUHP_AP_KVM_STARTING](cpu);
		break;
	}
	return NOTIFY_OK;
}

static int kvmclock_cpu_notifier(struct notifier_block *nfb,
                                       unsigned long action, void *hcpu)
{
	unsigned int cpu = raw_smp_processor_id();
	switch (action) {
	case CPU_ONLINE:
	case CPU_DOWN_FAILED:
		kvm_cpu_notifier_startup[CPUHP_AP_X86_KVM_CLK_ONLINE](cpu);
		break;
	case CPU_DOWN_PREPARE:
		kvm_cpu_notifier_teardown[CPUHP_AP_X86_KVM_CLK_ONLINE](cpu);
		break;
	}
	return NOTIFY_OK;
}
 

static struct notifier_block kvm_cpu_notifier[] = {
	[CPUHP_AP_KVM_STARTING] = {
		.notifier_call = kvm_cpu_hotplug,
	},
	[CPUHP_AP_X86_KVM_CLK_ONLINE] = {
		.notifier_call = kvmclock_cpu_notifier,
		.priority = -INT_MAX
	}
};

static void call_fn(void *info)
{
	unsigned int cpu = raw_smp_processor_id();
	kvm_cpu_notifier_startup[CPUHP_AP_X86_KVM_CLK_ONLINE](cpu);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
int cpuhp_setup_state(enum kvm_cpuhp_state state,
		      const char *name,
		      int (*startup)(unsigned int cpu),
		      int (*teardown)(unsigned int cpu))
{
	int cpu;
	BUG_ON(state != CPUHP_AP_X86_KVM_CLK_ONLINE);
	kvm_cpu_notifier_startup[state] = startup;
	kvm_cpu_notifier_teardown[state] = teardown;

	cpu_notifier_register_begin();
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, (void *)call_fn, NULL, 1);

	__register_hotcpu_notifier(&kvm_cpu_notifier[state]);
	cpu_notifier_register_done();
	return 0;
}

int cpuhp_setup_state_nocalls(enum kvm_cpuhp_state state,
			      const char *name,
			      int (*startup)(unsigned int cpu),
			      int (*teardown)(unsigned int cpu))
{
	BUG_ON(state == CPUHP_AP_X86_KVM_CLK_ONLINE);
	kvm_cpu_notifier_startup[state] = startup;
	kvm_cpu_notifier_teardown[state] = teardown;
	return register_cpu_notifier(&kvm_cpu_notifier[state]);
}

void cpuhp_remove_state_nocalls(enum kvm_cpuhp_state state)
{
	if (state == CPUHP_AP_X86_KVM_CLK_ONLINE)
		unregister_hotcpu_notifier(&kvm_cpu_notifier[state]);
	else
		unregister_cpu_notifier(&kvm_cpu_notifier[state]);
}
#endif

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)

#include <linux/kthread.h>

struct kthread_worker *
kthread_create_worker(unsigned int flags, const char namefmt[], ...)
{
	struct kthread_worker *worker;
	va_list args;
	struct task_struct *task;
	char comm[sizeof(task->comm) + 1];

	WARN_ON(flags);
	va_start(args, namefmt);
	vsnprintf(comm, sizeof(task->comm), namefmt, args);
	va_end(args);

	worker = kzalloc(sizeof(*worker), GFP_KERNEL);
	if (!worker)
		return ERR_PTR(-ENOMEM);

	kthread_init_worker(worker);
	task = kthread_run(kthread_worker_fn, worker, "%s", comm);
	if (IS_ERR(task))
		goto fail_task;

	flush_kthread_worker(worker);
	WARN_ON(worker->task != task);
	return worker;

fail_task:
	kfree(worker);
	return ERR_CAST(task);
}
EXPORT_SYMBOL(kthread_create_worker);

void kthread_destroy_worker(struct kthread_worker *worker)
{
	struct task_struct *task;

	task = worker->task;
	if (WARN_ON(!task))
		return;

	kthread_flush_worker(worker);
	kthread_stop(task);
	WARN_ON(!list_empty(&worker->work_list));
	kfree(worker);
}
EXPORT_SYMBOL(kthread_destroy_worker);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
long kvm_get_user_pages(unsigned long start, unsigned long nr_pages,
		 	unsigned int gup_flags, struct page **pages,
			struct vm_area_struct **vmas)
{
	return get_user_pages(current, current->mm, start, nr_pages,
			      !!(gup_flags & FOLL_WRITE),
			      !!(gup_flags & FOLL_FORCE),
			      pages, vmas);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
long kvm_get_user_pages(unsigned long start, unsigned long nr_pages,
		 	unsigned int gup_flags, struct page **pages,
			struct vm_area_struct **vmas)
{
	return get_user_pages(current, current->mm, start, nr_pages,
			      !!(gup_flags & FOLL_WRITE),
			      !!(gup_flags & FOLL_FORCE),
			      pages, vmas);
}
#else
long kvm_get_user_pages(unsigned long start, unsigned long nr_pages,
		 	unsigned int gup_flags, struct page **pages,
			struct vm_area_struct **vmas)
{
	return get_user_pages(start, nr_pages,
			      !!(gup_flags & FOLL_WRITE),
			      !!(gup_flags & FOLL_FORCE),
			      pages, vmas);
}
#endif

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
#include <linux/vmalloc.h>

/**
 * kvmalloc_node - attempt to allocate physically contiguous memory, but upon
 * failure, fall back to non-contiguous (vmalloc) allocation.
 * @size: size of the request.
 * @flags: gfp mask for the allocation - must be compatible (superset) with GFP_KERNEL.
 * @node: numa node to allocate from
 *
 * Uses kmalloc to get the memory but if the allocation fails then falls back
 * to the vmalloc allocator. Use kvfree for freeing the memory.
 *
 * Reclaim modifiers - __GFP_NORETRY, __GFP_REPEAT and __GFP_NOFAIL are not supported
 *
 * Any use of gfp flags outside of GFP_KERNEL should be consulted with mm people.
 */
void *kvmalloc_node(size_t size, gfp_t flags, int node)
{
	gfp_t kmalloc_flags = flags;
	void *ret;

	/*
	 * vmalloc uses GFP_KERNEL for some internal allocations (e.g page tables)
	 * so the given set of flags has to be compatible.
	 */
	WARN_ON_ONCE((flags & GFP_KERNEL) != GFP_KERNEL);

	/*
	 * Make sure that larger requests are not too disruptive - no OOM
	 * killer and no allocation failure warnings as we have a fallback
	 */
	if (size > PAGE_SIZE)
		kmalloc_flags |= __GFP_NORETRY | __GFP_NOWARN;

	ret = kmalloc_node(size, kmalloc_flags, node);

	/*
	 * It doesn't really make sense to fallback to vmalloc for sub page
	 * requests
	 */
	if (ret || size <= PAGE_SIZE)
		return ret;

	if (flags & __GFP_ZERO)
		return vzalloc_node(size, node);
	else
		return vmalloc_node(size, node);
}
EXPORT_SYMBOL(kvmalloc_node);
#endif
