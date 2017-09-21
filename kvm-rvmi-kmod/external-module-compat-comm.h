
/*
 * Compatibility header for building as an external module.
 */

/*
 * Avoid picking up the kernel's kvm.h in case we have a newer one.
 */

#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <linux/kconfig.h>
#include <linux/cpu.h>
#include <linux/pci.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/kernel.h>
#include <asm/processor.h>
#include <linux/hrtimer.h>
#include <asm/bitops.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#include <linux/kconfig.h>
#endif

#include "kvm-kmod-config.h"

/*
 * 2.6.16 does not have GFP_NOWAIT
 */

#include <linux/gfp.h>

#ifndef GFP_NOWAIT
#define GFP_NOWAIT (GFP_ATOMIC & ~__GFP_HIGH)
#endif


/*
 * kvm profiling support needs 2.6.20
 */
#include <linux/profile.h>

#ifndef KVM_PROFILING
#define KVM_PROFILING 1234
#define prof_on       4321
#endif

/*
 * smp_call_function_single() is not exported below 2.6.20, and has different
 * semantics below 2.6.23.  The 'nonatomic' argument was removed in 2.6.27.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

int kvm_smp_call_function_single(int cpu, void (*func)(void *info),
				 void *info, int wait);
#undef smp_call_function_single
#define smp_call_function_single kvm_smp_call_function_single

#endif

/* on_each_cpu() lost an argument in 2.6.27. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

#define kvm_on_each_cpu(func, info, wait) on_each_cpu(func, info, 0, wait)

#else

#define kvm_on_each_cpu(func, info, wait) on_each_cpu(func, info, wait)

#endif

#include <linux/notifier.h>
#ifndef CPU_TASKS_FROZEN

#define CPU_TASKS_FROZEN       0x0010
#define CPU_ONLINE_FROZEN      (CPU_ONLINE | CPU_TASKS_FROZEN)
#define CPU_UP_PREPARE_FROZEN  (CPU_UP_PREPARE | CPU_TASKS_FROZEN)
#define CPU_UP_CANCELED_FROZEN (CPU_UP_CANCELED | CPU_TASKS_FROZEN)
#define CPU_DOWN_PREPARE_FROZEN        (CPU_DOWN_PREPARE | CPU_TASKS_FROZEN)
#define CPU_DOWN_FAILED_FROZEN (CPU_DOWN_FAILED | CPU_TASKS_FROZEN)
#define CPU_DEAD_FROZEN                (CPU_DEAD | CPU_TASKS_FROZEN)

#endif

#ifndef CPU_DYING
#define CPU_DYING 0x000A
#define CPU_DYING_FROZEN (CPU_DYING | CPU_TASKS_FROZEN)
#endif

struct inode;

#include <linux/fs.h>
#include <linux/anon_inodes.h>

/* anon_inodes on RHEL >= 5.2 is equivalent to 2.6.27 version */
#ifdef RHEL_RELEASE_CODE
#  if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,2)) && defined(CONFIG_ANON_INODES)
#    define RHEL_ANON_INODES
#  endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) && !defined(RHEL_ANON_INODES)

static inline int kvm_anon_inode_getfd(const char *name,
				       const struct file_operations *fops,
				       void *priv, int flags)
{
	int r;
	int fd;
	struct inode *inode;
	struct file *file;

	r = anon_inode_getfd(&fd, &inode, &file, name, fops, priv);
	if (r < 0)
		return r;
	return fd;
}

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,26) && !defined(RHEL_ANON_INODES)

#define kvm_anon_inode_getfd(name, fops, priv, flags) \
	anon_inode_getfd(name, fops, priv)
}

#else /* > 2.6.26 || RHEL_ANON_INODES */

#define kvm_anon_inode_getfd	anon_inode_getfd

#endif /* > 2.6.26 || RHEL_ANON_INODES */

/* div64_u64 is fairly new */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

#define div64_u64 kvm_div64_u64

#ifdef CONFIG_64BIT

static inline uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	return dividend / divisor;
}

#else

uint64_t div64_u64(uint64_t dividend, uint64_t divisor);

#endif

#endif

/*
 * PF_VCPU is a Linux 2.6.24 addition
 */

#include <linux/sched.h>

#ifndef PF_VCPU
#define PF_VCPU 0
#endif

/*
 * smp_call_function_mask() is not defined/exported below 2.6.24 on all
 * targets and below 2.6.26 on x86-64
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) || \
    (defined CONFIG_X86_64 && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))

int kvm_smp_call_function_mask(cpumask_t mask, void (*func) (void *info),
			       void *info, int wait);

#define smp_call_function_mask kvm_smp_call_function_mask

void kvm_smp_send_reschedule(int cpu);

#else

#define kvm_smp_send_reschedule smp_send_reschedule

#endif

/* __mmdrop() is not exported before 2.6.25 */
#include <linux/sched.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define mmdrop(x) do { (void)(x); } while (0)
#define mmget(x) do { (void)(x); } while (0)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)

#define mmget(x) do { atomic_inc(x); } while (0)

#endif

#ifdef KVM_NEED_PAGEFAULT_DISABLE

static inline void pagefault_disable(void)
{
	inc_preempt_count();
	/*
	 * make sure to have issued the store before a pagefault
	 * can hit.
	 */
	barrier();
}

static inline void pagefault_enable(void)
{
	/*
	 * make sure to issue those last loads/stores before enabling
	 * the pagefault handler again.
	 */
	barrier();
	dec_preempt_count();
	/*
	 * make sure we do..
	 */
	barrier();
	preempt_check_resched();
}

#endif

/* simple vfs attribute getter signature has changed to add a return code */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static u64 x(void *v)                 \
	{				      \
		u64 ret = 0;		      \
					      \
		__##x(v, &ret);		      \
		return ret;		      \
	}

#else

#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static int x(void *v, u64 *val)	      \
	{				      \
		return __##x(v, val);	      \
	}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#ifndef FASTCALL
#define FASTCALL(x)	x
#define fastcall
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

static inline void flush_work(struct work_struct *work)
{
	cancel_work_sync(work);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)

#include <linux/mm.h>

static inline int kvm___get_user_pages_fast(unsigned long start, int nr_pages,
					    int write, struct page **pages)
{
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

static inline int get_user_pages_fast(unsigned long start, int nr_pages,
				      int write, struct page **pages)
{
	int npages;

	down_read(&current->mm->mmap_sem);
	npages = get_user_pages(current, current->mm, start, nr_pages, write,
				0, pages, NULL);
	up_read(&current->mm->mmap_sem);

	return npages;
}

#endif /* < 2.6.27 */

#else /* >= 2.6.37 */

#define kvm___get_user_pages_fast	__get_user_pages_fast

#endif /* >= 2.6.37 */

/* spin_needbreak() was called something else in 2.6.24 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)

#define spin_needbreak need_lockbreak

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

static inline void kvm_hrtimer_add_expires_ns(struct hrtimer *timer, u64 delta)
{
	timer->expires = ktime_add_ns(timer->expires, delta);
}

static inline ktime_t kvm_hrtimer_get_expires(struct hrtimer *timer)
{
	return timer->expires;
}

static inline u64 kvm_hrtimer_get_expires_ns(struct hrtimer *timer)
{
	return ktime_to_ns(timer->expires);
}

static inline void kvm_hrtimer_start_expires(struct hrtimer *timer, int mode)
{
	hrtimer_start(timer, timer->expires, mode);
}

static inline ktime_t kvm_hrtimer_expires_remaining(const struct hrtimer *timer)
{
    return ktime_sub(timer->expires, timer->base->get_time());
}

#else

#define kvm_hrtimer_add_expires_ns hrtimer_add_expires_ns
#define kvm_hrtimer_get_expires hrtimer_get_expires
#define kvm_hrtimer_get_expires_ns hrtimer_get_expires_ns
#define kvm_hrtimer_start_expires hrtimer_start_expires
#define kvm_hrtimer_expires_remaining hrtimer_expires_remaining

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#include <linux/pci.h>

static inline int __pci_reset_function(struct pci_dev *dev)
{
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static inline int pci_reset_function(struct pci_dev *dev)
{
	return 0;
}
#endif /* < 2.6.28 */
#endif /* < 2.6.31 */

/* dynamically allocated cpu masks introduced in 2.6.28 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

typedef cpumask_t cpumask_var_t[1];

static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return 1;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline void cpumask_clear(cpumask_var_t mask)
{
	cpus_clear(*mask);
}

static inline void cpumask_set_cpu(int cpu, cpumask_var_t mask)
{
	cpu_set(cpu, *mask);
}

static inline int smp_call_function_many(cpumask_var_t cpus,
					 void (*func)(void *data), void *data,
					 int sync)
{
	return smp_call_function_mask(*cpus, func, data, sync);
}

static inline int cpumask_empty(cpumask_var_t mask)
{
	return cpus_empty(*mask);
}

static inline int cpumask_test_cpu(int cpu, cpumask_var_t mask)
{
	return cpu_isset(cpu, *mask);
}

static inline void cpumask_clear_cpu(int cpu, cpumask_var_t mask)
{
	cpu_clear(cpu, *mask);
}

#define cpu_online_mask (&cpu_online_map)

#define cpumask_any(m) first_cpu(*(m))

#endif

/* A zeroing constructor was added late 2.6.30 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	bool ret;

	ret = alloc_cpumask_var(mask, flags);
	if (ret)
		cpumask_clear(*mask);
	return ret;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)

#define IF_ANON_INODES_DOES_REFCOUNTS(x)

#else

#define IF_ANON_INODES_DOES_REFCOUNTS(x) x

#endif


/* Macro introduced only on newer kernels: */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define marker_synchronize_unregister() synchronize_sched()
#endif

#ifdef NEED_COMPOUND_HEAD

static inline struct page *compound_head(struct page *page)
{
	if (PageCompound(page))
		page = (struct page *)page_private(page);
	return page;
}

#endif

#include <linux/iommu.h>
#ifndef IOMMU_CACHE

#define IOMMU_CACHE	(4)
#define IOMMU_CAP_CACHE_COHERENCY	0x1
static inline int iommu_domain_has_cap(struct iommu_domain *domain,
				       unsigned long cap)
{
	return 0;
}

#endif

#ifndef IOMMU_CAP_INTR_REMAP
#define IOMMU_CAP_INTR_REMAP		0x2	/* isolates device intrs */
#endif

/*
 * Tracepoints were introduced in 2.6.28, but changed several times in
 * incompatible ways.
 */

#include <linux/tracepoint.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

struct tracepoint;

#undef DECLARE_TRACE
#undef DEFINE_TRACE
#undef PARAMS
#undef TP_PROTO
#undef TP_ARGS
#undef EXPORT_TRACEPOINT_SYMBOL
#undef EXPORT_TRACEPOINT_SYMBOL_GPL

#define DECLARE_TRACE(name, proto, args)				\
	static inline void _do_trace_##name(struct tracepoint *tp, proto) \
	{ }								\
	static inline void trace_##name(proto)				\
	{ }								\
	static inline int register_trace_##name(void (*probe)(proto))	\
	{								\
		return -ENOSYS;						\
	}								\
	static inline int unregister_trace_##name(void (*probe)(proto))	\
	{								\
		return -ENOSYS;						\
	}

#define tracepoint_update_probe_range(begin, end) do {} while (0)

#define DEFINE_TRACE(name)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)
#define EXPORT_TRACEPOINT_SYMBOL(name)

#define PARAMS(args...) args
#define TP_PROTO(args...)	args
#define TP_ARGS(args...)		args

#define TRACE_EVENT(name, proto, args, struct, assign, print)	\
	DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

#undef tracepoint_synchronize_unregister
#define tracepoint_synchronize_unregister() do {} while (0)

#define DECLARE_EVENT_CLASS(name, proto, args, tstruct, assign, print)
#define DEFINE_EVENT(template, name, proto, args)		\
	DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

#define __print_hex(buf, buf_len)	(buf)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

#include <linux/trace_seq.h>

#define __print_hex(buf, buf_len)	ftrace_print_hex_seq(p, buf, buf_len)

static inline const char *
ftrace_print_hex_seq(struct trace_seq *p, const unsigned char *buf,
		     int buf_len)
{
	int i;
	const char *ret = p->buffer + p->len;

	for (i = 0; i < buf_len; i++)
		trace_seq_printf(p, "%s%2.2x", i == 0 ? "" : " ", buf[i]);

	if (p->full)
		return ret;

	if (p->len >= (PAGE_SIZE - 1)) {
		p->full = 1;
		return ret;
	}

	p->buffer[p->len++] = 0;

	return ret;
}
#endif

#include <linux/ftrace_event.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

struct trace_print_flags {
	unsigned long		mask;
	const char		*name;
};

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#define alloc_pages_exact_node alloc_pages_node

#endif

#include <linux/hugetlb.h>

/* vma_kernel_pagesize, exported since 2.6.32 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)

#if defined(CONFIG_HUGETLB_PAGE) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
static inline
unsigned long kvm_vma_kernel_pagesize(struct vm_area_struct *vma)
{
	struct hstate *hstate;

	if (!is_vm_hugetlb_page(vma))
		return PAGE_SIZE;

	hstate = hstate_vma(vma);

	return 1UL << (hstate->order + PAGE_SHIFT);
}
#else /* !CONFIG_HUGETLB_SIZE || <= 2.6.26 */
#define kvm_vma_kernel_pagesize(v) PAGE_SIZE
#endif

#else /* >= 2.6.32 */

#define kvm_vma_kernel_pagesize vma_kernel_pagesize

#endif

#ifndef printk_once
/*
 * Print a one-time message (analogous to WARN_ONCE() et al):
 */
#define printk_once(x...) ({			\
	static int __print_once = 1;		\
						\
	if (__print_once) {			\
		__print_once = 0;		\
		printk(x);			\
	}					\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) && !defined(CONFIG_CPU_FREQ)
static inline unsigned int cpufreq_get(unsigned int cpu)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
int schedule_hrtimeout(ktime_t *expires, const enum hrtimer_mode mode);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#ifndef CONFIG_MMU_NOTIFIER
struct mmu_notifier {};
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
static inline void hlist_del_init_rcu(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		n->pprev = NULL;
	}
}
#endif

#ifndef CONFIG_USER_RETURN_NOTIFIER

#include <linux/percpu.h>

struct kvm_user_return_notifier {
	void (*on_user_return)(struct kvm_user_return_notifier *urn);
};

DECLARE_PER_CPU(struct kvm_user_return_notifier *, kvm_urn);

static inline void
kvm_user_return_notifier_register(struct kvm_user_return_notifier *urn)
{
	__get_cpu_var(kvm_urn) = urn;
}

static inline void
kvm_user_return_notifier_unregister(struct kvm_user_return_notifier *urn)
{
	__get_cpu_var(kvm_urn) = NULL;
}

static inline void kvm_fire_urn(void)
{
	struct kvm_user_return_notifier *urn = __get_cpu_var(kvm_urn);

	if (urn)
		urn->on_user_return(urn);
}

#else /* CONFIG_USER_RETURN_NOTIFIER */

#define kvm_user_return_notifier		user_return_notifier
#define kvm_user_return_notifier_register	user_return_notifier_register
#define kvm_user_return_notifier_unregister	user_return_notifier_unregister

static inline void kvm_fire_urn(void) {}

#endif /* CONFIG_USER_RETURN_NOTIFIER */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#ifdef CONFIG_SMP
void kvm_synchronize_srcu_expedited(struct srcu_struct *sp);
#define kvm_synchronize_srcu kvm_synchronize_srcu_expedited
#else
static inline void kvm_synchronize_srcu_expedited(struct srcu_struct *sp) { }
static inline void kvm_synchronize_srcu(struct srcu_struct *sp) { }
#endif

#else

#define kvm_synchronize_srcu_expedited synchronize_srcu_expedited
#define kvm_synchronize_srcu synchronize_srcu

#endif

int kvm_init_srcu(void);
void kvm_exit_srcu(void);

#ifndef WARN_ONCE
#define WARN_ONCE(condition, format...)	({			\
	static bool __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN_ON(!__warned)) 			\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})
#endif

#ifndef WARN
#define WARN(condition, format...)	WARN_ON(condition)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define get_online_cpus lock_cpu_hotplug
#define put_online_cpus unlock_cpu_hotplug
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && KERNEL_EXTRAVERSION < 9)
static inline void kvm_getboottime(struct timespec *ts)
{
	struct timespec sys, now = current_kernel_time();
	ktime_get_ts(&sys);
	*ts = ns_to_timespec(timespec_to_ns(&now) - timespec_to_ns(&sys));
}
#define kvm_monotonic_to_bootbased(ts)
#else
#define kvm_getboottime			getboottime
#define kvm_monotonic_to_bootbased	monotonic_to_bootbased
#endif

static inline void kvm_clock_warn_suspend_bug(void)
{
#if defined(CONFIG_SUSPEND) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
     (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && KERNEL_EXTRAVERSION < 9))
	printk("kvm: paravirtual wallclock will not work reliably "
	       "accross host suspend/resume\n");
#endif
}

#if defined(CONFIG_PCI) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) && \
    (!defined(CONFIG_SUSE_KERNEL) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))
#include <linux/pci.h>
static inline struct pci_dev *
pci_get_domain_bus_and_slot(int domain, unsigned int bus, unsigned int devfn)
{
	if (domain != 0)
		return NULL;
	return pci_get_bus_and_slot(bus, devfn);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#define DEFINE_RAW_SPINLOCK		DEFINE_SPINLOCK
#define raw_spinlock_t			spinlock_t
#define raw_spin_lock_init		spin_lock_init
#define raw_spin_lock			spin_lock
#define raw_spin_lock_irqsave		spin_lock_irqsave
#define raw_spin_unlock			spin_unlock
#define raw_spin_unlock_irqrestore	spin_unlock_irqrestore
#define raw_spin_is_locked		spin_is_locked

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
struct perf_guest_info_callbacks {
	int (*is_in_guest) (void);
	int (*is_user_mode) (void);
	unsigned long (*get_guest_ip) (void);
};

static inline int
perf_register_guest_info_callbacks(struct perf_guest_info_callbacks *cbs)
{
	return 0;
}

static inline int
perf_unregister_guest_info_callbacks(struct perf_guest_info_callbacks *cbs)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define rcu_dereference_check(p, sp)	rcu_dereference(p)
#define rcu_dereference_protected(p, c)	rcu_dereference(p)
#define srcu_dereference(p, sp)		rcu_dereference(p)
#define srcu_read_lock_held(sp)		(1)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define lockdep_is_held(m)		(1)
#endif

#ifndef lower_32_bits
#define lower_32_bits(n) ((u32)(n))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define EHWPOISON	133	/* Memory page has hardware error */
#define FOLL_HWPOISON	0x100	/* check page is hwpoisoned */

static inline int 
__get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		 unsigned long start, int len, unsigned int foll_flags,
		 struct page **pages, struct vm_area_struct **vmas,
		 int *nonblocking)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	return is_hwpoison_address(start) ? -EHWPOISON : -ENOSYS;
#else
	return -ENOSYS;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#include <asm/siginfo.h>

typedef struct {
	int si_signo;
	int si_errno;
	int si_code;

	union {
		int _pad[SI_PAD_SIZE];

		struct _sigfault {
			void __user *_addr; /* faulting insn/memory ref. */
#ifdef __ARCH_SI_TRAPNO
			int _trapno;	/* TRAP # which caused the signal */
#endif
			short _addr_lsb; /* LSB of the reported address */
		} _sigfault;
	} _sifields;
} kvm_siginfo_t;

#define si_addr_lsb	_sifields._sigfault._addr_lsb
#define BUS_MCEERR_AR	(__SI_FAULT|4)

#else

#define kvm_siginfo_t	siginfo_t

#endif

#include <linux/mm.h>

/* Services below are only referenced by code unused in older kernels */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
static inline void kvm_use_mm(struct mm_struct *mm)
{
	BUG();
}

static inline void kvm_unuse_mm(struct mm_struct *mm)
{
	BUG();
}
#else
#define kvm_use_mm	use_mm
#define kvm_unuse_mm	unuse_mm
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static inline u32 hash_32(u32 val, unsigned int bits)
{
	BUG();
	return 0;
}
#define order_base_2(n)	({ BUG(); 0; })
#endif

#ifndef __rcu
#define __rcu
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && \
    (!defined(CONFIG_FEDORA_KERNEL) || \
     (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,35) && \
      KERNEL_EXTRAVERSION < 11) || \
     LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
#include <linux/vmalloc.h>
static inline void *vzalloc(unsigned long size)
{
	void *addr = vmalloc(size);
	if (addr)
		memset(addr, 0, size);
	return addr;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#include <linux/interrupt.h>

#define IRQF_ONESHOT	0x00002000

static inline int
kvm_request_threaded_irq(unsigned int irq, irq_handler_t handler,
                         irq_handler_t thread_fn,
                         unsigned long flags, const char *name, void *dev)
{
	return -ENOSYS;
}
#else
#define kvm_request_threaded_irq	request_threaded_irq
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define compound_trans_head(page) compound_head(page)

static inline int PageTransCompound(struct page *page)
{
        return 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,33)
#define kvm___this_cpu_read(n)		__get_cpu_var(n)
#define kvm___this_cpu_write(n, v)	__get_cpu_var(n) = v
#else /* > 2.6.33 */
#define kvm___this_cpu_read		__this_cpu_read
#define kvm___this_cpu_write		__this_cpu_write
#endif /* > 2.6.33 */

#ifndef __noclone
#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 5
#define __noclone	__attribute__((__noclone__))
#else /* !GCC || GCC < 4.5 */
#define __noclone
#endif /* !GCC || GCC < 4.5 */
#endif /* !__noclone */

#ifndef FOLL_NOWAIT
#define FOLL_NOWAIT	0x20
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#include <linux/delay.h>

static inline void flush_work_sync(struct work_struct *work)
{
	flush_work(work);
	/* pragmatic sync as we have no way to wait explicitly */
	msleep(100);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define __set_bit_le	ext2_set_bit
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static inline void rcu_virt_note_context_switch(int cpu)
{
}
#endif

#ifdef CONFIG_COMPAT
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
#include <linux/compat.h>
static inline
void kvm_sigset_from_compat(sigset_t *set, compat_sigset_t *compat)
{
	switch (_NSIG_WORDS) {
	case 4: set->sig[3] = compat->sig[6] | (((long)compat->sig[7]) << 32 );
	case 3: set->sig[2] = compat->sig[4] | (((long)compat->sig[5]) << 32 );
	case 2: set->sig[1] = compat->sig[2] | (((long)compat->sig[3]) << 32 );
	case 1: set->sig[0] = compat->sig[0] | (((long)compat->sig[1]) << 32 );
	}
}
#else /* >= 3.1 */
#define kvm_sigset_from_compat	sigset_from_compat
#endif /* >= 3.1 */
#endif /* CONFIG_COMPAT */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#ifdef CONFIG_PRINTK
#define printk_ratelimited(fmt, ...)					\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		printk(fmt, ##__VA_ARGS__);				\
})
#else
#define printk_ratelimited(fmt, ...)
#endif

#define pr_err_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_INFO fmt, ##__VA_ARGS__)
#if defined(DEBUG)
#define pr_debug_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define pr_debug_ratelimited(fmt, ...)
#endif

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

#define pr_warn_ratelimited	pr_warning_ratelimited

#endif /* < 2.6.35 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static inline int kvm_sched_info_on(void)
{
#ifdef CONFIG_SCHEDSTATS
        return 1;
#else
        return 0;
#endif
}
#else /* >= 3.1 */
#define kvm_sched_info_on sched_info_on
#endif /* >= 3.1 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#define PCI_DEV_FLAGS_ASSIGNED	0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#define iommu_present(x)	iommu_found()
#define iommu_domain_alloc(x)	iommu_domain_alloc()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static inline int test_and_set_bit_le(int nr, void *addr)
{
        return test_and_set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define for_each_set_bit(bit, addr, size) for_each_bit(bit, addr, size)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
struct kvm_x86_pmu_capability {
	int		version;
	int		num_counters_gp;
	int		num_counters_fixed;
	int		bit_width_gp;
	int		bit_width_fixed;
	unsigned int	events_mask;
	int		events_mask_len;
};

static inline void
kvm_perf_get_x86_pmu_capability(struct kvm_x86_pmu_capability *cap)
{
	memset(cap, 0, sizeof(*cap));
}
#else /* >= 3.3 */
#define kvm_x86_pmu_capability		x86_pmu_capability
#define kvm_perf_get_x86_pmu_capability	perf_get_x86_pmu_capability
#endif /* >= 3.3 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define PCI_STD_RESOURCES	0
#define PCI_STD_RESOURCE_END	5
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static inline int
kvm_path_put(struct path *path)
{
	BUG();
	return -EPERM;
}
#else /* >= 2.6.25 */
#define kvm_path_put		path_put
#endif /* >= 2.6.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static inline int kvm_inode_permission(struct inode *inode, int mask)
{
	BUG();
	return -EPERM;
}
#else /* >= 2.6.28 */
#define kvm_inode_permission	inode_permission
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static inline int
kvm_kern_path(const char *name, unsigned int flags, struct path *path)
{
	return -EPERM;
}
#else /* >= 2.6.28 */
#define kvm_kern_path		kern_path
#endif /* >= 2.6.28 */

#ifndef MAY_ACCESS
#define MAY_ACCESS		0x00000010
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#include <linux/uaccess.h>
static inline void *memdup_user(const void __user *user, size_t size)
{
	void *buf = kzalloc(size, GFP_KERNEL);

	if (!buf)
		return ERR_PTR(-ENOMEM);
	if (copy_from_user(buf, user, size))
		return ERR_PTR(-EFAULT);
	return buf;
}
#endif /* < 2.6.30 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
static inline void debugfs_remove_recursive(struct dentry *dentry)
{
	WARN("kvm-kmod: leaving some debugfs entries behind");
}
#endif /* < 2.6.27 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static inline bool pci_intx_mask_supported(struct pci_dev *dev)
{
	return false;
}

static inline bool pci_check_and_mask_intx(struct pci_dev *dev)
{
	BUG();
	return false;
}

static inline bool pci_check_and_unmask_intx(struct pci_dev *dev)
{
	BUG();
	return false;
}
#endif /* < 3.3 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define IRQ_WAKE_THREAD		IRQ_NONE	/* will never be used */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
struct x86_cpu_id { };
#define X86_FEATURE_MATCH(x) { }
#endif /* < 3.4 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define kvm_kmap_atomic(page)	kmap_atomic(page, KM_USER0)
#define kvm_kunmap_atomic(page)	kunmap_atomic(page, KM_USER0)
#else /* >= 2.6.37 */
#define kvm_kmap_atomic		kmap_atomic
#define kvm_kunmap_atomic	kunmap_atomic
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#include <linux/workqueue.h>
#define kthread_worker			workqueue_struct *
#define kthread_work			work_struct
#define queue_kthread_work(q, w)	queue_work(*(q), w)
#define flush_kthread_work		cancel_work_sync
#define init_kthread_work		INIT_WORK
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
static inline unsigned long vm_mmap(struct file *file, unsigned long addr,
				    unsigned long len, unsigned long prot,
				    unsigned long flag, unsigned long offset)
{
	unsigned long ret;
	struct mm_struct *mm = current->mm;

	down_write(&mm->mmap_sem);
	ret = do_mmap(file, addr, len, prot, flag, offset);
	up_write(&mm->mmap_sem);
	return ret;
}

static inline int vm_munmap(unsigned long start, size_t len)
{
	struct mm_struct *mm = current->mm;
	int ret;

	down_write(&mm->mmap_sem);
	ret = do_munmap(mm, start, len);
	up_write(&mm->mmap_sem);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#include <linux/highmem.h>
static inline int is_vmalloc_addr(const void *x)
{
	unsigned long addr = (unsigned long)x;

	return addr >= VMALLOC_START && addr < VMALLOC_END;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static inline void
kvm_set_normalized_timespec(struct timespec *ts, time_t sec, s64 nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		/*
		 * The following asm() prevents the compiler from
		 * optimising this loop into a modulo operation. See
		 * also __iter_div_u64_rem() in include/linux/time.h
		 */
		asm("" : "+rm"(nsec));
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		asm("" : "+rm"(nsec));
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

static inline struct timespec kvm_timespec_sub(struct timespec lhs,
					       struct timespec rhs)
{
	struct timespec ts_delta;
	kvm_set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
				    lhs.tv_nsec - rhs.tv_nsec);
	return ts_delta;
}
#else
#define kvm_timespec_sub	timespec_sub
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
struct kvm_static_key {
};
struct kvm_static_key_deferred {
};
#define kvm_static_key_false(key)		(1)
#define kvm_static_key_slow_inc(key)		do { } while (0)
#define kvm_static_key_slow_dec(key)		do { } while (0)
#define kvm_static_key_slow_dec_deferred(key)	do { } while (0)
#define kvm_jump_label_rate_limit(key, hz)	do { } while (0)
#else /* >= 3.7.0 */
#define kvm_static_key				static_key
#define kvm_static_key_deferred			static_key_deferred
#define kvm_static_key_false			static_key_false
#define kvm_static_key_slow_inc			static_key_slow_inc
#define kvm_static_key_slow_dec			static_key_slow_dec
#define kvm_static_key_slow_dec_deferred	static_key_slow_dec_deferred
#define kvm_jump_label_rate_limit		jump_label_rate_limit
#endif /* >= 3.7.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define mutex_lock_killable(m)			({ mutex_lock(m); 0; })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define vtime_account_system			account_system_vtime
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#define vtime_account_system			vtime_account
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define vtime_account_system			vtime_account_system_irqsafe
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
static inline void set_bit_le(int nr, void *addr)
{
	set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}
#endif

#ifndef SHRT_MAX
#define USHRT_MAX	((u16)(~0U))
#define SHRT_MAX	((s16)(USHRT_MAX>>1))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#include <linux/pci.h>
#include <linux/list.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#include <linux/rculist.h>
#endif

#define hlist_entry_safe(ptr, type, member) \
	(ptr) ? hlist_entry(ptr, type, member) : NULL

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member)					\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define hlist_first_rcu(head)	(*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)	(*((struct hlist_node __rcu **)(&(node)->next)))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define rcu_dereference_raw	rcu_dereference
#endif

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#endif /* < 3.9 */

#ifndef __percpu
#define __percpu
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#if defined(CONFIG_CONTEXT_TRACKING) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
extern void guest_enter(void);
extern void guest_exit(void);

#else /* !CONFIG_CONTEXT_TRACKING */
static inline void guest_enter(void)
{
	vtime_account_system(current);
	current->flags |= PF_VCPU;
}

static inline void guest_exit(void)
{
	vtime_account_system(current);
	current->flags &= ~PF_VCPU;
}
#endif /* !CONFIG_CONTEXT_TRACKING */
#endif /* < 3.10 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
#include <linux/context_tracking.h>
static inline void guest_enter_irqoff(void)
{
	guest_enter();
	if (!context_tracking_cpu_is_enabled())
		rcu_virt_note_context_switch(smp_processor_id());
}

static inline void guest_exit_irqoff(void)
{
	guest_exit();
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static inline void smp_mb__after_srcu_read_unlock(void) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define pci_enable_msix_exact	pci_enable_msix
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)addr, PAGE_SIZE)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
static inline bool ktime_before(const ktime_t cmp1, const ktime_t cmp2)
{
        return ktime_compare(cmp1, cmp2) < 0;
}
#endif

/*
 * Timekeeping code switched from timespec- to nanosecond-based in 3.17.
 * The more complicated computations are done with auxiliary functions
 * rather than directly in the sync script.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
extern u64 ktime_get_boot_ns(void);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
struct timekeeper;
extern u64 kvm_get_boot_base_ns(struct timekeeper *tk);
#endif
#endif

#ifndef FOLL_TRIED
#define FOLL_TRIED 0
#endif

#undef is_zero_pfn
#define is_zero_pfn(pfn) ((pfn) == page_to_pfn(ZERO_PAGE(0)))

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18, 0)
#define iommu_capable(dummy, cap) \
    iommu_domain_has_cap(kvm->arch.iommu_domain, cap)

static inline void pci_clear_dev_assigned(struct pci_dev *pdev)
{
	pdev->dev_flags &= ~PCI_DEV_FLAGS_ASSIGNED;
}

static inline void pci_set_dev_assigned(struct pci_dev *pdev)
{
	pdev->dev_flags |= PCI_DEV_FLAGS_ASSIGNED;
}

#undef percpu_counter_init
#define percpu_counter_init(fbc, value, gfp)                            \
        ({                                                              \
                static struct lock_class_key __key;                     \
                                                                        \
                __percpu_counter_init(fbc, value, &__key);              \
        })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,3)
void *get_xsave_addr(struct xsave_struct *xsave, int feature);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
bool single_task_running(void);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#define trace_seq_buffer_ptr(p) ((p)->buffer + (p)->len)
#endif

#ifndef CONFIG_CONTEXT_TRACKING
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static bool context_tracking_cpu_is_enabled(void) { return false; }
static bool context_tracking_is_enabled(void) { return false; }
#endif
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define context_tracking_cpu_is_enabled() context_tracking_active()
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
#define d_backing_inode(path) ((path)->d_inode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#define preempt_notifier_inc()
#define preempt_notifier_dec()
#define smp_store_mb(p, val) set_mb(p, val)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
static inline struct page *
__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	return alloc_pages_exact_node(nid, gfp_mask, order);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
/* Not exported until 4.4.  */
void task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st);

#ifndef mul_u64_u64_shr
static inline u64 mul_u64_u64_shr(u64 a, u64 b, unsigned int shift)
{
	union {
		u64 ll;
		struct {
#ifdef __BIG_ENDIAN
			u32 high, low;
#else
			u32 low, high;
#endif
		} l;
	} rl, rm, rn, rh, a0, b0;
	u64 c;

	a0.ll = a;
	b0.ll = b;

	rl.ll = (u64)a0.l.low * b0.l.low;
	rm.ll = (u64)a0.l.low * b0.l.high;
	rn.ll = (u64)a0.l.high * b0.l.low;
	rh.ll = (u64)a0.l.high * b0.l.high;

	/*
	 * Each of these lines computes a 64-bit intermediate result into "c",
	 * starting at bits 32-95.  The low 32-bits go into the result of the
	 * multiplication, the high 32-bits are carried into the next step.
	 */
	rl.l.high = c = (u64)rl.l.high + rm.l.low + rn.l.low;
	rh.l.low = c = (c >> 32) + rm.l.high + rn.l.high + rh.l.low;
	rh.l.high = (c >> 32) + rh.l.high;

	/*
	 * The 128-bit result of the multiplication is in rl.ll and rh.ll,
	 * shift it right and throw away the high part of the result.
	 */
	if (shift == 0)
		return rl.ll;
	if (shift < 64)
		return (rl.ll >> shift) | (rh.ll << (64 - shift));
	return rh.ll >> (shift & 63);
}
#endif /* mul_u64_u64_shr */

#ifndef mul_u64_u32_div
static inline u64 mul_u64_u32_div(u64 a, u32 mul, u32 divisor)
{
	union {
		u64 ll;
		struct {
#ifdef __BIG_ENDIAN
			u32 high, low;
#else
			u32 low, high;
#endif
		} l;
	} u, rl, rh;

	u.ll = a;
	rl.ll = (u64)u.l.low * mul;
	rh.ll = (u64)u.l.high * mul + rl.l.high;

	/* Bits 32-63 of the result will be in rh.l.low. */
	rl.l.high = do_div(rh.ll, divisor);

	/* Bits 0-31 of the result will be in rl.l.low.	*/
	do_div(rl.ll, divisor);

	rl.l.high = rh.l.low;
	return rl.ll;
}
#endif /* mul_u64_u32_div */
#endif

#ifndef FOLL_REMOTE
#define FOLL_REMOTE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
/*
 * PageTransCompoundMap is the same as PageTransCompound, but it also
 * guarantees the primary MMU has the entire compound page mapped
 * through pmd_trans_huge, which in turn guarantees the secondary MMUs
 * can also map the entire compound page. This allows the secondary
 * MMUs to call get_user_pages() only once for each compound page and
 * to immediately map the entire compound page with a single secondary
 * MMU fault. If there will be a pmd split later, the secondary MMUs
 * will get an update through the MMU notifier invalidation through
 * split_huge_pmd().
 *
 * Unlike PageTransCompound, this is safe to be called only while
 * split_huge_pmd() cannot run from under us, like if protected by the
 * MMU notifier, otherwise it may result in page->_mapcount < 0 false
 * positives.
 */
static inline int PageTransCompoundMap(struct page *page)
{
        return PageTransCompound(page) && atomic_read(&page->_mapcount) < 0;
}

static inline void intel_pt_handle_vmx(int on)
{
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#include <linux/time64.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
#if __BITS_PER_LONG == 64
static inline struct timespec timespec64_to_timespec(const struct timespec64 ts64)
{
       return ts64;
}

static inline struct timespec64 timespec_to_timespec64(const struct timespec ts)
{
       return ts;
}
#else
static inline struct timespec timespec64_to_timespec(const struct timespec64 ts64)
{
       struct timespec ret;

       ret.tv_sec = (time_t)ts64.tv_sec;
       ret.tv_nsec = ts64.tv_nsec;
       return ret;
}

static inline struct timespec64 timespec_to_timespec64(const struct timespec ts)
{
       struct timespec64 ret;

       ret.tv_sec = ts.tv_sec;
       ret.tv_nsec = ts.tv_nsec;
       return ret;
}

#endif
#endif

static inline void getboottime64(struct timespec64 *ts64)
{
	struct timespec ts;

	kvm_getboottime(&ts);
	*ts64 = timespec_to_timespec64(ts);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
int kvm_fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm,
       			 unsigned long address, unsigned int flags,
			 bool *unlocked);

enum kvm_cpuhp_state {
	CPUHP_AP_KVM_STARTING,
	CPUHP_AP_X86_KVM_CLK_ONLINE,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
int cpuhp_setup_state(enum kvm_cpuhp_state state,
	     	      const char *name,
	      	      int (*startup)(unsigned int cpu),
	      	      int (*teardown)(unsigned int cpu));
int cpuhp_setup_state_nocalls(enum kvm_cpuhp_state state,
                              const char *name,
                              int (*startup)(unsigned int cpu),
                              int (*teardown)(unsigned int cpu));
void cpuhp_remove_state_nocalls(enum kvm_cpuhp_state state);
#endif

#else
#define kvm_fixup_user_fault fixup_user_fault
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
long kvm_get_user_pages(unsigned long start, unsigned long nr_pages,
		 	unsigned int gup_flags, struct page **pages,
			struct vm_area_struct **vmas);
    
struct kthread_worker;
void kthread_destroy_worker(struct kthread_worker *worker);
struct kthread_worker *kthread_create_worker(unsigned int flags,
					     const char namefmt[], ...);

#define __kthread_init_worker __init_kthread_worker
#define kthread_init_worker   init_kthread_worker
#define kthread_init_work     init_kthread_work
#define kthread_insert_work   insert_kthread_work
#define kthread_queue_work    queue_kthread_work
#define kthread_flush_work    flush_kthread_work
#define kthread_flush_worker  flush_kthread_worker

#ifndef __ro_after_init
#define __ro_after_init
#endif

#else
#define kvm_get_user_pages get_user_pages
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
long kvm_get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
			       unsigned long start, unsigned long nr_pages,
			       unsigned int gup_flags, struct page **pages,
			       struct vm_area_struct **vmas, int *locked);
long kvm_get_user_pages_unlocked(unsigned long start, unsigned long nr_pages,
				 struct page **pages, unsigned int gup_flags);

#include <linux/jump_label_ratelimit.h>
static inline void static_key_deferred_flush(struct static_key_deferred *key)
{
	flush_delayed_work(&key->work);
}

#else
#define kvm_get_user_pages_remote get_user_pages_remote
#define kvm_get_user_pages_unlocked get_user_pages_unlocked
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
static inline void kvm_mmget(struct mm_struct *mm)
{
       atomic_inc(&mm->mm_users);
}

static inline void kvm_mmgrab(struct mm_struct *mm)
{
       atomic_inc(&mm->mm_count);
}
#else
#define kvm_mmget mmget
#define kvm_mmgrab mmgrab
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
extern void *kvmalloc_node(size_t size, gfp_t flags, int node);
static inline void *kvmalloc(size_t size, gfp_t flags)
{
	return kvmalloc_node(size, flags, NUMA_NO_NODE);
}
static inline void *kvzalloc_node(size_t size, gfp_t flags, int node)
{
	return kvmalloc_node(size, flags | __GFP_ZERO, node);
}
static inline void *kvzalloc(size_t size, gfp_t flags)
{
	return kvmalloc(size, flags | __GFP_ZERO);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
static inline void __cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	__set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static inline void __cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	__clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

#define wait_queue_entry_t wait_queue_t
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
#define X86_FEATURE_SHA_NI	( 9*32+29)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#define MSR_IA32_MCG_EXT_CTL		0x000004d0
#define FEATURE_CONTROL_LMCE		(1<<20)
#define MCG_EXT_CTL_LMCE_EN         (1ULL<<0)
#define MCG_LMCE_P					(1ULL<<27)   /* Local machine check supported */
#endif

