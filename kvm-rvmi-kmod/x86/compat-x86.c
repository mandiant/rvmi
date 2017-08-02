
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

unsigned int kvm_xstate_size;

void kvm_xstate_size_init(void)
{
	unsigned int eax, ebx, ecx, edx;

	/*  kvm only uses xstate_size if xsave is supported */
	if (cpu_has_xsave) {
		cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
		kvm_xstate_size = ebx;
		BUG_ON(kvm_xstate_size > sizeof(union kvm_thread_xstate));
	}
}

#endif /* < 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

const int kvm_amd_erratum_383[] =
	AMD_OSVW_ERRATUM(3, AMD_MODEL_RANGE(0x10, 0, 0, 0xff, 0xf));

EXPORT_SYMBOL_GPL(kvm_amd_erratum_383);

#endif /* < 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) && defined(CONFIG_KVM_GUEST)
void kvm_async_pf_task_wait(u32 token)
{
	BUG();
}
EXPORT_SYMBOL_GPL(kvm_async_pf_task_wait);

void kvm_async_pf_task_wake(u32 token)
{
	BUG();
}
EXPORT_SYMBOL_GPL(kvm_async_pf_task_wake);

u32 kvm_read_and_reset_pf_reason(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_and_reset_pf_reason);
#endif /* < 2.6.38 && CONFIG_KVM_GUEST */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)

#ifndef SVM_CPUID_FUNC
#define SVM_CPUID_FUNC 0x8000000a
#endif

#define SVM_FEATURE_NPT            (1 <<  0)
#define SVM_FEATURE_LBRV           (1 <<  1)
#define SVM_FEATURE_NRIP           (1 <<  3)
#define SVM_FEATURE_FLUSH_ASID     (1 <<  6)
#define SVM_FEATURE_DECODE_ASSIST  (1 <<  7)
#define SVM_FEATURE_PAUSE_FILTER   (1 << 10)

bool kvm_boot_cpu_has(unsigned int bit)
{
	static u32 svm_features;
	static bool initialized;

	if (!initialized) {
		svm_features = cpuid_edx(SVM_CPUID_FUNC);
		initialized = true;
	}
	switch (bit) {
	case X86_FEATURE_NPT:
		return svm_features & SVM_FEATURE_NPT;
	case X86_FEATURE_LBRV:
		return svm_features & SVM_FEATURE_LBRV;
	case X86_FEATURE_NRIPS:
		return svm_features & SVM_FEATURE_NRIP;
	case X86_FEATURE_FLUSHBYASID:
		return svm_features & SVM_FEATURE_FLUSH_ASID;
	case X86_FEATURE_DECODEASSISTS:
		return svm_features & SVM_FEATURE_DECODE_ASSIST;
	case X86_FEATURE_PAUSEFILTER:
		return svm_features & SVM_FEATURE_PAUSE_FILTER;
	default:
		return boot_cpu_has(bit);
	}
}
EXPORT_SYMBOL_GPL(kvm_boot_cpu_has);
#endif /* < 2.6.37 */

#include <asm/desc.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
DEFINE_PER_CPU(struct kvm_desc_ptr, kvm_host_gdt);
EXPORT_SYMBOL_GPL(kvm_host_gdt);

static inline void kvm_native_load_gdt(const struct kvm_desc_ptr *dtr)
{
	asm volatile("lgdt %0"::"m" (*dtr));
}

static inline void kvm_native_store_gdt(struct kvm_desc_ptr *dtr)
{
	asm volatile("sgdt %0":"=m" (*dtr));
}

void load_fixmap_gdt(int processor_id)
{
	kvm_native_load_gdt(this_cpu_ptr(&kvm_host_gdt));
}
EXPORT_SYMBOL_GPL(load_fixmap_gdt);

void kvm_do_store_gdt(void)
{
	kvm_native_store_gdt(this_cpu_ptr(&kvm_host_gdt));
}

unsigned int mxcsr_feature_mask __read_mostly = 0xffffffffu;
EXPORT_SYMBOL_GPL(mxcsr_feature_mask);
#endif

