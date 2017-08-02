
/*
 * Compatibility header for building as an external module.
 */

#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/kconfig.h>

#include <linux/types.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

typedef u64 phys_addr_t;

#endif

#include <asm/cpufeature.h>

#ifndef X86_FEATURE_HYPERVISOR
#define X86_FEATURE_HYPERVISOR	(4*32+31) /* Running on a hypervisor */
#endif

#ifndef cpu_has_hypervisor
#define cpu_has_hypervisor boot_cpu_has(X86_FEATURE_HYPERVISOR)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
#include <linux/string.h>
#include <asm/processor.h>
static inline uint32_t hypervisor_cpuid_base(const char *sig, uint32_t leaves)
{
	uint32_t base, eax, signature[3];

	for (base = 0x40000000; base < 0x40010000; base += 0x100) {
		cpuid(base, &eax, &signature[0], &signature[1], &signature[2]);

		if (!memcmp(sig, signature, 12) &&
		    (leaves == 0 || ((eax - base) >= leaves)))
			return base;
	}

	return 0;
}
#endif

#include "../external-module-compat-comm.h"

#include <asm/msr.h>
#include <asm/asm.h>
#include <asm/desc.h>

#ifndef CONFIG_HAVE_KVM_EVENTFD
#define CONFIG_HAVE_KVM_EVENTFD 1
#endif

#ifndef CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT
#define CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT 1
#endif

#ifndef CONFIG_KVM_APIC_ARCHITECTURE
#define CONFIG_KVM_APIC_ARCHITECTURE
#endif

#ifndef CONFIG_KVM_MMIO
#define CONFIG_KVM_MMIO
#endif

#ifndef CONFIG_KVM_ASYNC_PF
#define CONFIG_KVM_ASYNC_PF 1
#endif

#ifndef CONFIG_HAVE_KVM_MSI
#define CONFIG_HAVE_KVM_MSI 1
#endif

#ifndef CONFIG_HAVE_KVM_IRQCHIP
#define CONFIG_HAVE_KVM_IRQCHIP 1
#endif

#ifndef CONFIG_HAVE_KVM_IRQ_ROUTING
#define CONFIG_HAVE_KVM_IRQ_ROUTING 1
#endif

#ifndef CONFIG_HAVE_KVM_IRQFD
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define CONFIG_HAVE_KVM_IRQFD 1
#endif
#endif

#if !defined(CONFIG_KVM_DEVICE_ASSIGNMENT) && defined(CONFIG_PCI) && \
    defined(CONFIG_IOMMU_API)
#define CONFIG_KVM_DEVICE_ASSIGNMENT 1
#endif

#ifndef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
#define CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#ifdef CONFIG_X86_64
#define DECLARE_ARGS(val, low, high)	unsigned low, high
#define EAX_EDX_VAL(val, low, high)	((low) | ((u64)(high) << 32))
#define EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#else
#define DECLARE_ARGS(val, low, high)	unsigned long long val
#define EAX_EDX_VAL(val, low, high)	(val)
#define EAX_EDX_ARGS(val, low, high)	"A" (val)
#define EAX_EDX_RET(val, low, high)	"=A" (val)
#endif

#ifndef __ASM_EX_SEC
# define __ASM_EX_SEC	" .section __ex_table,\"a\"\n"
#endif

#ifndef _ASM_EXTABLE
# define _ASM_EXTABLE(from,to) \
        __ASM_EX_SEC    \
        _ASM_ALIGN "\n" \
        _ASM_PTR #from "," #to "\n" \
        " .previous\n"
#endif

#ifndef __ASM_SEL
#ifdef CONFIG_X86_32
# define __ASM_SEL(a,b) __ASM_FORM(a)
#else
# define __ASM_SEL(a,b) __ASM_FORM(b)
#endif
#endif

#ifndef __ASM_FORM
# define __ASM_FORM(x)	" " #x " "
#endif

#ifndef _ASM_PTR
#define _ASM_PTR	__ASM_SEL(.long, .quad)
#endif

#ifndef _ASM_ALIGN
#define _ASM_ALIGN	__ASM_SEL(.balign 4, .balign 8)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) || defined(CONFIG_X86_64)

static inline unsigned long long native_read_msr_safe(unsigned int msr,
						      int *err)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("2: rdmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=r" (*err), EAX_EDX_RET(val, low, high)
		     : "c" (msr), [fault] "i" (-EFAULT));
	return EAX_EDX_VAL(val, low, high);
}

#endif

static inline int kvm_native_write_msr_safe(unsigned int msr,
					    unsigned low, unsigned high)
{
	int err;
	asm volatile("2: wrmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=a" (err)
		     : "c" (msr), "0" (low), "d" (high),
		       [fault] "i" (-EIO)
		     : "memory");
	return err;
}

#else /* >= 2.6.25 */

#define kvm_native_write_msr_safe	native_write_msr_safe

#endif /* >= 2.6.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

static inline int rdmsrl_safe(unsigned msr, unsigned long long *p)
{
	int err;

	*p = native_read_msr_safe(msr, &err);
	return err;
}

#endif

#ifndef MSR_KERNEL_GS_BASE
#define MSR_KERNEL_GS_BASE              0xc0000102
#endif

#ifndef MSR_TSC_AUX
#define MSR_TSC_AUX                     0xc0000103
#endif

#ifndef MSR_K8_TSEG_MASK
#define MSR_K8_TSEG_MASK		0xc0010113
#endif

#ifndef MSR_VM_CR
#define MSR_VM_CR                       0xc0010114
#endif

#ifndef MSR_VM_HSAVE_PA
#define MSR_VM_HSAVE_PA                 0xc0010117
#endif

#ifndef MSR_F15H_IC_CFG
#define MSR_F15H_IC_CFG			0xc0011021
#endif

#ifndef _EFER_SVME
#define _EFER_SVME		12
#define EFER_SVME		(1<<_EFER_SVME)
#endif

#ifndef _EFER_FFXSR
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */
#define EFER_FFXSR		(1<<_EFER_FFXSR)
#endif

#ifndef MSR_STAR
#define MSR_STAR                0xc0000081
#endif

#ifndef MSR_K8_INT_PENDING_MSG
#define MSR_K8_INT_PENDING_MSG  0xc0010055
#endif

#ifndef MSR_IA32_BNDCFGS_RSVD
#define MSR_IA32_BNDCFGS_RSVD	0x00000ffc
#endif

#ifndef X86_FEATURE_CLFLUSH
#define X86_FEATURE_CLFLUSH	(0*32+19)
#endif

#ifndef X86_FEATURE_FXSR_OPT
#define X86_FEATURE_FXSR_OPT	(1*32+25)
#endif

#ifndef X86_FEATURE_GBPAGES
#define X86_FEATURE_GBPAGES	(1*32+26) /* GB pages */
#endif

#ifndef X86_FEATURE_NX
#define X86_FEATURE_NX		(1*32+20) /* Execute Disable */
#endif

#ifndef X86_FEATURE_PCLMULQDQ
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* PCLMULQDQ instruction */
#endif

#ifndef X86_FEATURE_VMX
#define X86_FEATURE_VMX		(4*32+ 5) /* Hardware virtualization */
#endif

#ifndef X86_FEATURE_SSSE3
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental SSE-3 */
#endif

#ifndef X86_FEATURE_FMA
#define X86_FEATURE_FMA		(4*32+12) /* Fused multiply-add */
#endif

#ifndef X86_FEATURE_PCID
#define X86_FEATURE_PCID	(4*32+17) /* Process Context Identifiers */
#endif

#ifndef X86_FEATURE_XMM4_1
#define X86_FEATURE_XMM4_1	(4*32+19) /* "sse4_1" SSE-4.1 */
#endif

#ifndef X86_FEATURE_XMM4_2
#define X86_FEATURE_XMM4_2	(4*32+20) /* "sse4_2" SSE-4.2 */
#endif

#ifndef X86_FEATURE_X2APIC
#define X86_FEATURE_X2APIC	(4*32+21) /* x2APIC */
#endif

#ifndef X86_FEATURE_MOVBE
#define X86_FEATURE_MOVBE	(4*32+22) /* MOVBE instruction */
#endif

#ifndef X86_FEATURE_POPCNT
#define X86_FEATURE_POPCNT	(4*32+23) /* POPCNT instruction */
#endif

#ifndef X86_FEATURE_TSC_DEADLINE_TIMER
#define X86_FEATURE_TSC_DEADLINE_TIMER	(4*32+24) /* Tsc deadline timer */
#endif

#ifndef X86_FEATURE_AES
#define X86_FEATURE_AES		(4*32+25) /* AES instructions */
#endif

#ifndef X86_FEATURE_XSAVE
#define X86_FEATURE_XSAVE	(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#endif

#ifndef X86_FEATURE_OSXSAVE
#define X86_FEATURE_OSXSAVE	(4*32+27) /* "" XSAVE enabled in the OS */
#endif

#ifndef X86_FEATURE_AVX
#define X86_FEATURE_AVX		(4*32+28) /* Advanced Vector Extensions */
#endif

#ifndef X86_FEATURE_F16C
#define X86_FEATURE_F16C	(4*32+29) /* 16-bit fp conversions */
#endif

#ifndef X86_FEATURE_RDRAND
#define X86_FEATURE_RDRAND	(4*32+30) /* The RDRAND instruction */
#endif

#ifndef X86_FEATURE_SVM
#define X86_FEATURE_SVM		(6*32+ 2) /* Secure virtual machine */
#endif

#ifndef X86_FEATURE_CR8_LEGACY
#define X86_FEATURE_CR8_LEGACY	(6*32+ 4) /* CR8 in 32-bit mode */
#endif

#ifndef X86_FEATURE_ABM
#define X86_FEATURE_ABM		(6*32+ 5) /* Advanced bit manipulation */
#endif

#ifndef X86_FEATURE_SSE4A
#define X86_FEATURE_SSE4A	(6*32+ 6) /* SSE-4A */
#endif

#ifndef X86_FEATURE_MISALIGNSSE
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#endif

#ifndef X86_FEATURE_3DNOWPREFETCH
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#endif

#ifndef X86_FEATURE_OSVW
#define X86_FEATURE_OSVW	(6*32+ 9) /* OS Visible Workaround */
#endif

#ifndef X86_FEATURE_XOP
#define X86_FEATURE_XOP		(6*32+11) /* extended AVX instructions */
#endif

#ifndef X86_FEATURE_FMA4
#define X86_FEATURE_FMA4	(6*32+16) /* 4 operands MAC instructions */
#endif

#ifndef X86_FEATURE_TBM
#define X86_FEATURE_TBM		(6*32+21) /* trailing bit manipulations */
#endif

#ifndef X86_FEATURE_NPT
#define X86_FEATURE_NPT		(8*32+ 5) /* AMD Nested Page Table support */
#endif

#ifndef X86_FEATURE_LBRV
#define X86_FEATURE_LBRV	(8*32+ 6) /* AMD LBR Virtualization support */
#endif

#ifndef X86_FEATURE_NRIPS
#define X86_FEATURE_NRIPS	(8*32+ 8) /* "nrip_save" AMD SVM next_rip save */
#endif

#ifndef X86_FEATURE_TSCRATEMSR
#define X86_FEATURE_TSCRATEMSR  (8*32+ 9) /* "tsc_scale" AMD TSC scaling support */
#endif

#ifndef X86_FEATURE_FLUSHBYASID
#define X86_FEATURE_FLUSHBYASID (8*32+11) /* AMD flush-by-ASID support */
#endif

#ifndef X86_FEATURE_DECODEASSISTS
#define X86_FEATURE_DECODEASSISTS (8*32+12) /* AMD Decode Assists support */
#endif

#ifndef X86_FEATURE_PAUSEFILTER
#define X86_FEATURE_PAUSEFILTER (8*32+13) /* AMD filtered pause intercept */
#endif

#ifndef X86_FEATURE_FSGSBASE
#define X86_FEATURE_FSGSBASE	(9*32+ 0) /* {RD/WR}{FS/GS}BASE instructions*/
#endif

#ifndef X86_FEATURE_TSC_ADJUST
#define X86_FEATURE_TSC_ADJUST	(9*32+ 1) /* TSC adjustment MSR 0x3b */
#endif

#ifndef X86_FEATURE_BMI1
#define X86_FEATURE_BMI1	(9*32+ 3) /* 1st group bit manipulation extensions */
#endif

#ifndef X86_FEATURE_HLE
#define X86_FEATURE_HLE		(9*32+ 4) /* Hardware Lock Elision */
#endif

#ifndef X86_FEATURE_AVX2
#define X86_FEATURE_AVX2	(9*32+ 5) /* AVX2 instructions */
#endif

#ifndef X86_FEATURE_SMEP
#define X86_FEATURE_SMEP	(9*32+ 7) /* Supervisor Mode Execution Protection */
#endif

#ifndef X86_FEATURE_BMI2
#define X86_FEATURE_BMI2	(9*32+ 8) /* 2nd group bit manipulation extensions */
#endif

#ifndef X86_FEATURE_ERMS
#define X86_FEATURE_ERMS	(9*32+ 9) /* Enhanced REP MOVSB/STOSB */
#endif

#ifndef X86_FEATURE_INVPCID
#define X86_FEATURE_INVPCID	(9*32+10) /* Invalidate Processor Context ID */
#endif

#ifndef X86_FEATURE_RTM
#define X86_FEATURE_RTM		(9*32+11) /* Restricted Transactional Memory */
#endif

#ifndef X86_FEATURE_MPX
#define X86_FEATURE_MPX		(9*32+14) /* Memory Protection Extension */
#endif

#ifndef X86_FEATURE_AVX512F
#define X86_FEATURE_AVX512F     (9*32+16) /* AVX-512 Foundation */
#endif

#ifndef X86_FEATURE_AVX512DQ
#define X86_FEATURE_AVX512DQ	(9*32+17) /* AVX-512 DQ (Double/Quad granular) Instructions */
#endif

#ifndef X86_FEATURE_AVX512IFMA
#define X86_FEATURE_AVX512IFMA  ( 9*32+21) /* AVX-512 Integer Fused Multiply-Add instructions */
#endif

#ifndef X86_FEATURE_CLWB
#define X86_FEATURE_CLWB	( 9*32+24) /* CLWB instruction */
#endif

#ifndef X86_FEATURE_PCOMMIT
#define X86_FEATURE_PCOMMIT	(9*32+22) /* PCOMMIT instruction */
#endif

#ifndef X86_FEATURE_AVX512PF
#define X86_FEATURE_AVX512PF    (9*32+26) /* AVX-512 Prefetch */
#endif

#ifndef X86_FEATURE_AVX512ER
#define X86_FEATURE_AVX512ER    (9*32+27) /* AVX-512 Exponential and Reciprocal */
#endif

#ifndef X86_FEATURE_AVX512CD
#define X86_FEATURE_AVX512CD    (9*32+28) /* AVX-512 Conflict Detection */
#endif

#ifndef X86_FEATURE_AVX512BW
#define X86_FEATURE_AVX512BW	(9*32+30) /* AVX-512 BW (Byte/Word granular) Instructions */
#endif

#ifndef X86_FEATURE_AVX512VL
#define X86_FEATURE_AVX512VL	(9*32+31) /* AVX-512 VL (128/256 Vector Length) Extensions */
#endif

#if X86_FEATURE_XSAVEOPT < 10 * 32
#undef X86_FEATURE_XSAVEOPT
#define X86_FEATURE_XSAVEOPT	(10*32+0) /* XSAVEOPT instruction */
#endif

#ifndef X86_FEATURE_XSAVEC
#define X86_FEATURE_XSAVEC	(10*32+1) /* XSAVEC instruction */
#endif

#ifndef X86_FEATURE_XGETBV1
#define X86_FEATURE_XGETBV1	(10*32+2) /* "XCR1" register */
#endif

#ifndef X86_FEATURE_XSAVES
#define X86_FEATURE_XSAVES	(10*32+3) /* XSAVES instruction */
#endif

#ifndef X86_FEATURE_AVIC
#define X86_FEATURE_AVIC	(15*32+13) /* Virtual Interrupt Controller */
#endif

#ifndef X86_FEATURE_VIRTUAL_VMLOAD_VMSAVE
#define X86_FEATURE_VIRTUAL_VMLOAD_VMSAVE (15*32+15)
#endif

#ifndef X86_FEATURE_AVX512VBMI
#define X86_FEATURE_AVX512VBMI  (16*32+ 1) /* AVX512 Vector Bit Manipulation instructions*/
#endif

#ifndef X86_FEATURE_UMIP
#define X86_FEATURE_UMIP	(16*32+ 2) /* User-Mode Instruction Prevention */
#endif

#ifndef X86_FEATURE_PKU
#define X86_FEATURE_PKU		(16*32+3) /* Protection Keys for Userspace */
#endif

#ifndef X86_FEATURE_OSPKE
#define X86_FEATURE_OSPKE	(16*32+ 4) /* OS Protection Keys Enable */
#endif

#ifndef X86_FEATURE_AVX512_VPOPCNTDQ
#define X86_FEATURE_AVX512_VPOPCNTDQ (16*32+14) /* POPCNT for vectors of DW/QW */
#endif

#ifndef X86_FEATURE_RDPID
#define X86_FEATURE_RDPID	(16*32+22) /* User-Mode Instruction Prevention */
#endif

#ifndef MSR_AMD64_PATCH_LOADER
#define MSR_AMD64_PATCH_LOADER         0xc0010020
#endif

#ifndef MSR_AMD64_TSC_RATIO
#define MSR_AMD64_TSC_RATIO		0xc0000104
#endif

#ifndef MSR_AMD64_BU_CFG2
#define MSR_AMD64_BU_CFG2		0xc001102a
#endif

#include <linux/smp.h>

#ifndef X86_CR0_PE
#define X86_CR0_PE 0x00000001
#endif

#ifndef X86_CR0_MP
#define X86_CR0_MP 0x00000002
#endif

#ifndef X86_CR0_EM
#define X86_CR0_EM 0x00000004
#endif

#ifndef X86_CR0_TS
#define X86_CR0_TS 0x00000008
#endif

#ifndef X86_CR0_ET
#define X86_CR0_ET 0x00000010
#endif

#ifndef X86_CR0_NE
#define X86_CR0_NE 0x00000020
#endif

#ifndef X86_CR0_WP
#define X86_CR0_WP 0x00010000
#endif

#ifndef X86_CR0_AM
#define X86_CR0_AM 0x00040000
#endif

#ifndef X86_CR0_NW
#define X86_CR0_NW 0x20000000
#endif

#ifndef X86_CR0_CD
#define X86_CR0_CD 0x40000000
#endif

#ifndef X86_CR0_PG
#define X86_CR0_PG 0x80000000
#endif

#ifndef X86_CR3_PWT
#define X86_CR3_PWT 0x00000008
#endif

#ifndef X86_CR3_PCD
#define X86_CR3_PCD 0x00000010
#endif

#ifndef X86_CR3_PCID_MASK
#define X86_CR3_PCID_MASK 0x00000fff
#endif

#ifndef X86_CR4_UMIP
#define X86_CR4_UMIP 0x00000800
#endif

#ifndef X86_CR4_VMXE
#define X86_CR4_VMXE 0x00002000
#endif

#ifndef X86_CR4_FSGSBASE
#define X86_CR4_FSGSBASE 0x00010000
#endif

#ifndef X86_CR4_PCIDE
#define X86_CR4_PCIDE 0x00020000
#endif

#ifndef X86_CR4_OSXSAVE
#define X86_CR4_OSXSAVE 0x00040000
#endif

#ifndef X86_CR4_SMEP
#define X86_CR4_SMEP 0x00100000
#endif

#ifndef X86_CR4_PKE
#define X86_CR4_PKE 0x00400000
#endif

#undef X86_CR8_TPR
#define X86_CR8_TPR 0x0f

#include <asm/pgtable_types.h>

#ifndef _PAGE_NOCACHE
#define _PAGE_NOCACHE _PAGE_CACHE_UC
#endif

#ifndef CONFIG_PREEMPT_NOTIFIERS

#ifdef CONFIG_HAVE_HW_BREAKPOINT
#error Preemption notifier emulation does not work for this kernel.
#endif

/*
 * Include sched|preempt.h before defining CONFIG_PREEMPT_NOTIFIERS to avoid
 * a miscompile.
 */
#include <linux/sched.h>
#include <linux/preempt.h>
#define CONFIG_PREEMPT_NOTIFIERS
#define CONFIG_PREEMPT_NOTIFIERS_COMPAT

struct preempt_notifier;

struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *notifier, int cpu);
	void (*sched_out)(struct preempt_notifier *notifier,
			  struct task_struct *next);
};

struct preempt_notifier {
	struct list_head link;
	struct task_struct *tsk;
	struct preempt_ops *ops;
};

void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);

static inline void preempt_notifier_init(struct preempt_notifier *notifier,
				     struct preempt_ops *ops)
{
	notifier->ops = ops;
}

void start_special_insn(void);
void end_special_insn(void);
void in_special_section(void);

void preempt_notifier_sys_init(void);
void preempt_notifier_sys_exit(void);

#else

static inline void start_special_insn(void) {}
static inline void end_special_insn(void) {}
static inline void in_special_section(void) {}

static inline void preempt_notifier_sys_init(void) {}
static inline void preempt_notifier_sys_exit(void) {}

#endif

/* CONFIG_HAS_IOMEM is apparently fairly new too (2.6.21 for x86_64). */
#ifndef CONFIG_HAS_IOMEM
#define CONFIG_HAS_IOMEM 1
#endif

#ifndef cpu_has_xsave
#define cpu_has_xsave boot_cpu_has(X86_FEATURE_XSAVE)
#endif

#ifndef cpu_has_xsaves
#define cpu_has_xsaves boot_cpu_has(X86_FEATURE_XSAVES)
#endif

/* EFER_LMA and EFER_LME are missing in pre 2.6.24 i386 kernels */
#ifndef EFER_LME
#define _EFER_LME           8  /* Long mode enable */
#define _EFER_LMA           10 /* Long mode active (read-only) */
#define EFER_LME            (1<<_EFER_LME)
#define EFER_LMA            (1<<_EFER_LMA)
#endif

#ifndef EFER_LMSLE
#define _EFER_LMSLE		13 /* Long Mode Segment Limit Enable */
#define EFER_LMSLE		(1<<_EFER_LMSLE)
#endif

struct kvm_desc_struct {
	union {
		struct { unsigned int a, b; };
		struct {
			u16 limit0;
			u16 base0;
			unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
			unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
		};

	};
} __attribute__((packed));

struct kvm_ldttss_desc64 {
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

struct kvm_desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

static inline unsigned long
kvm_get_desc_base(const struct kvm_desc_struct *desc)
{
	return (unsigned)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline void
kvm_set_desc_base(struct kvm_desc_struct *desc, unsigned long base)
{
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = (base >> 24) & 0xff;
}

static inline unsigned long
kvm_get_desc_limit(const struct kvm_desc_struct *desc)
{
	return desc->limit0 | (desc->limit << 16);
}

static inline void
kvm_set_desc_limit(struct kvm_desc_struct *desc, unsigned long limit)
{
	desc->limit0 = limit & 0xffff;
	desc->limit = (limit >> 16) & 0xf;
}

static inline void kvm_load_gdt(const struct kvm_desc_ptr *dtr)
{
	asm volatile("lgdt %0"::"m" (*dtr));
}

static inline void kvm_native_store_idt(struct kvm_desc_ptr *dtr)
{
	asm volatile("sidt %0":"=m" (*dtr));
}

#include <asm/msr.h>
#ifndef MSR_FS_BASE
#define MSR_FS_BASE 0xc0000100
#endif
#ifndef MSR_GS_BASE
#define MSR_GS_BASE 0xc0000101
#endif

#include <asm/hw_irq.h>
#ifndef NMI_VECTOR
#define NMI_VECTOR 2
#endif

#ifndef MSR_MTRRcap
#define MSR_MTRRcap            0x0fe
#define MSR_MTRRfix64K_00000   0x250
#define MSR_MTRRfix16K_80000   0x258
#define MSR_MTRRfix16K_A0000   0x259
#define MSR_MTRRfix4K_C0000    0x268
#define MSR_MTRRfix4K_C8000    0x269
#define MSR_MTRRfix4K_D0000    0x26a
#define MSR_MTRRfix4K_D8000    0x26b
#define MSR_MTRRfix4K_E0000    0x26c
#define MSR_MTRRfix4K_E8000    0x26d
#define MSR_MTRRfix4K_F0000    0x26e
#define MSR_MTRRfix4K_F8000    0x26f
#define MSR_MTRRdefType        0x2ff
#endif

#ifndef MSR_IA32_CR_PAT
#define MSR_IA32_CR_PAT        0x00000277
#endif

#ifndef MSR_VM_IGNNE
#define MSR_VM_IGNNE                    0xc0010115
#endif

/* Define DEBUGCTLMSR bits */
#ifndef DEBUGCTLMSR_LBR

#define _DEBUGCTLMSR_LBR	0 /* last branch recording */
#define _DEBUGCTLMSR_BTF	1 /* single-step on branches */

#define DEBUGCTLMSR_LBR		(1UL << _DEBUGCTLMSR_LBR)
#define DEBUGCTLMSR_BTF		(1UL << _DEBUGCTLMSR_BTF)

#endif

#ifndef MSR_FAM10H_MMIO_CONF_BASE
#define MSR_FAM10H_MMIO_CONF_BASE      0xc0010058
#endif

#ifndef MSR_AMD64_NB_CFG
#define MSR_AMD64_NB_CFG               0xc001001f
#endif

#include <asm/asm.h>

#ifndef __ASM_SIZE
# define ____ASM_FORM(x) " " #x " "
# ifdef CONFIG_X86_64
#  define __ASM_SIZE(inst) ____ASM_FORM(inst##q)
# else
#  define __ASM_SIZE(inst) ____ASM_FORM(inst##l)
# endif
#endif

#ifndef _ASM_PTR
# ifdef CONFIG_X86_64
#  define _ASM_PTR ".quad"
# else
#  define _ASM_PTR ".long"
# endif
#endif

/* Intel VT MSRs */
#ifndef MSR_IA32_VMX_BASIC
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#endif

#ifndef MSR_IA32_FEATURE_CONTROL
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED		(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED	(1<<2)
#endif

#ifndef FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1<<1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)
#endif

#ifndef MSR_IA32_TSC
#define MSR_IA32_TSC                    0x00000010
#endif

#ifndef MSR_K7_HWCR
#define MSR_K7_HWCR                     0xc0010015
#endif

#ifndef MSR_K8_SYSCFG
#define MSR_K8_SYSCFG                   0xc0010010
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25) && defined(__x86_64__)

#undef set_debugreg
#define set_debugreg(value, register) \
	__asm__("movq %0,%%db" #register \
		: /* no output */ \
		:"r" ((unsigned long)value))

#endif

#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define kvm_compat_debugreg(x) debugreg[x]
#else
#define kvm_compat_debugreg(x) debugreg##x
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)

struct mtrr_var_range {
	u32 base_lo;
	u32 base_hi;
	u32 mask_lo;
	u32 mask_hi;
};

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef u8 mtrr_type;

#define MTRR_NUM_FIXED_RANGES 88
#define MTRR_MAX_VAR_RANGES 256

struct mtrr_state_type {
	struct mtrr_var_range var_ranges[MTRR_MAX_VAR_RANGES];
	mtrr_type fixed_ranges[MTRR_NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
};

#endif

#include <asm/mce.h>

#ifndef MCG_CTL_P
#define MCG_CTL_P        (1ULL<<8)
#define MCG_STATUS_MCIP  (1ULL<<2)
#define MCI_STATUS_VAL   (1ULL<<63)
#define MCI_STATUS_OVER  (1ULL<<62)
#define MCI_STATUS_UC    (1ULL<<61)
#endif

#ifndef MCG_SER_P
#define MCG_SER_P	 	(1ULL<<24)   /* MCA recovery/new status bits */
#endif

/* do_machine_check() exported in 2.6.31 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

static inline void kvm_do_machine_check(struct pt_regs *regs, long error_code)
{
	panic("kvm machine check!\n");
}

#else

#define kvm_do_machine_check do_machine_check

#endif

/* pt_regs.flags was once pt_regs.eflags */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define kvm_pt_regs_flags eflags

#  ifdef CONFIG_X86_64
#    define kvm_pt_regs_cs cs
#  else
#    define kvm_pt_regs_cs xcs
#  endif

#else

#define kvm_pt_regs_flags flags
#define kvm_pt_regs_cs cs

#endif

/* boot_cpu_data.x86_phys_bits only appeared for i386 in 2.6.30 */

#if !defined(CONFIG_X86_64) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))

#define kvm_x86_phys_bits 40

#else

#define kvm_x86_phys_bits (boot_cpu_data.x86_phys_bits)

#endif

#include <asm/apicdef.h>

#ifndef APIC_BASE_MSR
#define APIC_BASE_MSR    0x800
#endif

#ifndef APIC_SPIV_DIRECTED_EOI
#define APIC_SPIV_DIRECTED_EOI          (1 << 12)
#endif

#ifndef APIC_LVR_DIRECTED_EOI
#define APIC_LVR_DIRECTED_EOI   (1 << 24)
#endif

#ifndef APIC_SELF_IPI
#define APIC_SELF_IPI    0x3F0
#endif

#ifndef X2APIC_ENABLE
#define X2APIC_ENABLE    (1UL << 10)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

static inline int hw_breakpoint_active(void)
{
	return test_thread_flag(TIF_DEBUG);
}

static inline void hw_breakpoint_restore(void)
{
	set_debugreg(current->thread.kvm_compat_debugreg(0), 0);
	set_debugreg(current->thread.kvm_compat_debugreg(1), 1);
	set_debugreg(current->thread.kvm_compat_debugreg(2), 2);
	set_debugreg(current->thread.kvm_compat_debugreg(3), 3);
	set_debugreg(current->thread.kvm_compat_debugreg(6), 6);
	set_debugreg(current->thread.kvm_compat_debugreg(7), 7);
}

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && defined(CONFIG_X86_64)
#define kvm_check_tsc_unstable()	1
#else
#define kvm_check_tsc_unstable		check_tsc_unstable
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define percpu_read(t)		__get_cpu_var(t)
#define percpu_write(t, v)	__get_cpu_var(t) = v
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && \
     KERNEL_EXTRAVERSION < 16) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,33) && \
     KERNEL_EXTRAVERSION < 6) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,34) && \
     KERNEL_EXTRAVERSION < 1)
#define kvm_tboot_enabled()	0
#else
#define kvm_tboot_enabled	tboot_enabled
#define KVM_TBOOT_ENABLED_WORKS	1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define PVCLOCK_TSC_STABLE_BIT (1 << 0)

struct kvm_pvclock_vcpu_time_info {
	u32   version;
	u32   pad0;
	u64   tsc_timestamp;
	u64   system_time;
	u32   tsc_to_system_mul;
	s8    tsc_shift;
	u8    flags;
	u8    pad[2];
} __attribute__((__packed__)); /* 32 bytes */
#else
#define kvm_pvclock_vcpu_time_info	pvclock_vcpu_time_info
#endif

#ifndef MSR_AMD64_DC_CFG
#define MSR_AMD64_DC_CFG		0xc0011022
#endif

#ifndef MSR_IA32_MCx_STATUS
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#endif

#include <asm/fpu/api.h>
#include <asm/fpu-internal.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
struct kvm_fxregs_state {
	u16	cwd;
	u16	swd;
	u16	twd;
	u16	fop;
	u64	rip;
	u64	rdp;
	u32	mxcsr;
	u32	mxcsr_mask;
	u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32	padding[12 + 12];
} __aligned(16);

struct kvm_ymmh_struct {
	/* 16 * 16 bytes for each YMMH-reg = 256 bytes */
	u32 ymmh_space[64];
};

struct kvm_xsave_hdr_struct {
	u64 xstate_bv;
	u64 reserved1[2];
	u64 reserved2[5];
} __attribute__((packed));

struct kvm_xregs_state {
	struct kvm_fxregs_state i387;
	struct kvm_xsave_hdr_struct xsave_hdr;
	struct kvm_ymmh_struct ymmh;
	/* new processor state extensions will go here */
} __attribute__ ((packed, aligned (64)));

union kvm_fpregs_state {
	struct kvm_fxregs_state fxsave;
	struct kvm_xregs_state xsave;
};

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0) /* && >= 2.6.35 */

#define kvm_fpregs_state	thread_xstate
#define kvm_xregs_state		xsave_struct
#define kvm_fxregs_state	i387_fxsave_struct

#else /* >= 4.2.0 */

#define kvm_fpregs_state	fpregs_state
#define kvm_xregs_state		xregs_state
#define kvm_fxregs_state	fxregs_state

#endif /* >= 4.2.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

struct kvm_compat_fpu {
	union kvm_fpregs_state state_buffer;
	union kvm_fpregs_state *state;
};

static inline int kvm_fpu_alloc(struct kvm_compat_fpu *fpu)
{
	fpu->state = &fpu->state_buffer;
	return 0;
}

static inline void kvm_fpu_free(struct kvm_compat_fpu *fpu)
{
}

static inline void kvm_fx_save(struct kvm_fxregs_state *image)
{
	asm("fxsave (%0)":: "r" (image));
}

static inline void kvm_fx_restore(struct kvm_fxregs_state *image)
{
	asm("fxrstor (%0)":: "r" (image));
}

static inline void kvm_fx_finit(void)
{
	asm("finit");
}

static inline void kvm_fpu_finit(struct kvm_compat_fpu *fpu)
{
	unsigned after_mxcsr_mask;

	preempt_disable();
	kvm_fx_finit();
	kvm_fx_save(&fpu->state->fxsave);
	preempt_enable();

	after_mxcsr_mask = offsetof(struct kvm_fxregs_state, st_space);
	fpu->state->fxsave.mxcsr = 0x1f80;
	memset((void *)&fpu->state->fxsave + after_mxcsr_mask,
	       0, sizeof(struct kvm_fxregs_state) - after_mxcsr_mask);
}

static inline int kvm_fpu_restore_checking(struct kvm_compat_fpu *fpu)
{
	kvm_fx_restore(&fpu->state->fxsave);
	return 0;
}

static inline void kvm_fpu_save_init(struct kvm_compat_fpu *fpu)
{
	kvm_fx_save(&fpu->state->fxsave);
}

extern unsigned int kvm_xstate_size;

void kvm_xstate_size_init(void);

#else /* >= 2.6.36 */

#define kvm_compat_fpu			fpu
#define kvm_fpu_alloc			fpu_alloc
#define kvm_fpu_free			fpu_free
#define kvm_fpu_restore_checking	fpu_restore_checking
#define kvm_fpu_save_init		fpu_save_init
#define kvm_fpu_finit			fpu_finit

#define kvm_xstate_size			xstate_size

static inline void kvm_xstate_size_init(void)
{
}

#endif /* >= 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
static inline int kvm_init_fpu(struct task_struct *tsk)
{
	__asm__ ("movups %xmm0, %xmm0");
	return 0;
}
#else /* >= 2.6.38 */
#define kvm_init_fpu	init_fpu
#endif /* >= 2.6.38 */

#ifndef XFEATURE_MASK_FP
#define XFEATURE_MASK_FP       0x1
#define XFEATURE_MASK_SSE      0x2
#define XFEATURE_MASK_FPSSE    (XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#endif

#ifndef XFEATURE_MASK_EXTEND
#define XFEATURE_MASK_EXTEND	(~(XFEATURE_MASK_FPSSE | (1ULL << 63)))
#endif

#ifndef XFEATURE_MASK_BNDREGS
#define XFEATURE_MASK_BNDREGS	0x8
#define XFEATURE_MASK_BNDCSR	0x10
#endif

#ifndef XFEATURE_MASK_YMM
#define XFEATURE_MASK_YMM      0x4
#endif

#ifndef XFEATURE_MASK_BNDCSR
#define XFEATURE_MASK_BNDREGS  0x8
#define XFEATURE_MASK_BNDCSR   0x10
#define XFEATURE_MASK_EAGER	(XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR)
#endif

#ifndef XFEATURE_MASK_OPMASK
#define XFEATURE_MASK_OPMASK           0x20
#define XFEATURE_MASK_ZMM_Hi256        0x40
#define XFEATURE_MASK_Hi16_ZMM         0x80
#endif

#ifndef XFEATURE_MASK_PKRU
#define XFEATURE_MASK_PKRU             0x200
#endif

#ifndef XFEATURE_MASK_AVX512
#define XFEATURE_MASK_AVX512   (XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | XFEATURE_MASK_Hi16_ZMM)
#endif

#ifndef FXSAVE_SIZE
#define FXSAVE_SIZE         512
#endif

#ifndef XSAVE_HDR_OFFSET
#define XSAVE_HDR_OFFSET    FXSAVE_SIZE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define kvm_cpu_has_xsave	0
#else /* >= 2.6.28 */
#define kvm_cpu_has_xsave	cpu_has_xsave
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

#ifndef AMD_OSVW_ERRATUM
#define AMD_OSVW_ERRATUM(osvw_id, ...)	{ osvw_id, __VA_ARGS__, 0 }
#endif

#ifndef AMD_MODEL_RANGE
#define AMD_MODEL_RANGE(f, m_start, s_start, m_end, s_end) \
	((f << 24) | (m_start << 16) | (s_start << 12) | (m_end << 4) | (s_end))
#define AMD_MODEL_RANGE_FAMILY(range)	(((range) >> 24) & 0xff)
#define AMD_MODEL_RANGE_START(range)	(((range) >> 12) & 0xfff)
#define AMD_MODEL_RANGE_END(range)	((range) & 0xfff)
#endif

#ifndef MSR_AMD64_OSVW_ID_LENGTH
#define MSR_AMD64_OSVW_ID_LENGTH	0xc0010140
#define MSR_AMD64_OSVW_STATUS		0xc0010141
#endif

extern const int kvm_amd_erratum_383[];

static inline bool kvm_cpu_has_amd_erratum(const int *erratum)
{
	struct cpuinfo_x86 *cpu = &current_cpu_data;
	int osvw_id = *erratum++;
	u32 range;
	u32 ms;

	/*
	 * If called early enough that current_cpu_data hasn't been initialized
	 * yet, fall back to boot_cpu_data.
	 */
	if (cpu->x86 == 0)
		cpu = &boot_cpu_data;

	if (cpu->x86_vendor != X86_VENDOR_AMD)
		return false;

	if (osvw_id >= 0 && osvw_id < 65536 &&
	    cpu_has(cpu, X86_FEATURE_OSVW)) {
		u64 osvw_len;

		rdmsrl(MSR_AMD64_OSVW_ID_LENGTH, osvw_len);
		if (osvw_id < osvw_len) {
			u64 osvw_bits;

			rdmsrl(MSR_AMD64_OSVW_STATUS + (osvw_id >> 6),
			    osvw_bits);
			return osvw_bits & (1ULL << (osvw_id & 0x3f));
		}
	}

	/* OSVW unavailable or ID unknown, match family-model-stepping range */
	ms = (cpu->x86_model << 4) | cpu->x86_mask;
	while ((range = *erratum++))
		if ((cpu->x86 == AMD_MODEL_RANGE_FAMILY(range)) &&
		    (ms >= AMD_MODEL_RANGE_START(range)) &&
		    (ms <= AMD_MODEL_RANGE_END(range)))
			return true;

	return false;
}

#else /* >= 2.6.36 */

#define kvm_cpu_has_amd_erratum	cpu_has_amd_erratum
#define kvm_amd_erratum_383	amd_erratum_383

#endif /* >= 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && \
    (LINUX_VERSION_CODE != KERNEL_VERSION(2,6,32) || KERNEL_EXTRAVERSION < 40)
static inline u64 pvclock_scale_delta(u64 delta, u32 mul_frac, int shift)
{
	u64 product;
#ifdef __i386__
	u32 tmp1, tmp2;
#else
	ulong tmp;
#endif

	if (shift < 0)
		delta >>= -shift;
	else
		delta <<= shift;

#ifdef __i386__
	__asm__ (
		"mul  %5       ; "
		"mov  %4,%%eax ; "
		"mov  %%edx,%4 ; "
		"mul  %5       ; "
		"xor  %5,%5    ; "
		"add  %4,%%eax ; "
		"adc  %5,%%edx ; "
		: "=A" (product), "=r" (tmp1), "=r" (tmp2)
		: "a" ((u32)delta), "1" ((u32)(delta >> 32)), "2" (mul_frac) );
#elif defined(__x86_64__)
	__asm__ (
		"mul %[mul_frac] ; shrd $32, %[hi], %[lo]"
		: [lo]"=a"(product),
		  [hi]"=d"(tmp)
		: "0"(delta),
		  [mul_frac]"rm"((u64)mul_frac));
#else
#error implement me!
#endif

	return product;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34) && \
    LINUX_VERSION_CODE != KERNEL_VERSION(2,6,32) && defined(CONFIG_X86_64)
#define kvm_set_64bit(ptr, val)	set_64bit((unsigned long *)ptr, val)
#else
#define kvm_set_64bit		set_64bit
#endif

#ifndef MSR_EBC_FREQUENCY_ID
#define MSR_EBC_FREQUENCY_ID	0x0000002c
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && defined(CONFIG_X86_64)
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define static_cpu_has(bit) boot_cpu_has(bit)
#endif

#ifndef MSR_IA32_BBL_CR_CTL3
#define MSR_IA32_BBL_CR_CTL3	0x0000011e
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
bool kvm_boot_cpu_has(unsigned int bit);
#else
#define kvm_boot_cpu_has	boot_cpu_has
#endif

#ifndef MSR_IA32_VMX_TRUE_PINBASED_CTLS
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490

#define VMX_BASIC_VMCS_SIZE_SHIFT	32
#define VMX_BASIC_MEM_TYPE_SHIFT	50
#define VMX_BASIC_MEM_TYPE_WB	6LLU
#endif

#ifndef MSR_IA32_TSCDEADLINE
#define MSR_IA32_TSCDEADLINE		0x000006e0
#endif

#ifndef APIC_LVT_TIMER_ONESHOT
#define APIC_LVT_TIMER_ONESHOT		(0 << 17)
#endif

#ifndef APIC_LVT_TIMER_TSCDEADLINE
#define APIC_LVT_TIMER_TSCDEADLINE	(2 << 17)
#endif

#ifndef MSR_IA32_MISC_ENABLE_FAST_STRING
#define MSR_IA32_MISC_ENABLE_FAST_STRING	(1ULL << 0)
#endif

#ifndef MSR_MISC_FEATURES_ENABLES
#define MSR_MISC_FEATURES_ENABLES                 0x00000140
#endif

#ifndef MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT
#define MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT 0
#endif

#ifndef MSR_MISC_FEATURES_ENABLES_CPUID_FAULT
#define MSR_MISC_FEATURES_ENABLES_CPUID_FAULT     BIT_ULL(MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT)
#endif

#ifndef MSR_PLATFORM_INFO
#define MSR_PLATFORM_INFO                 0x000000ce
#endif

#ifndef MSR_PLATFORM_INFO_CPUID_FAULT_BIT
#define MSR_PLATFORM_INFO_CPUID_FAULT_BIT 31
#endif

#ifndef MSR_PLATFORM_INFO_CPUID_FAULT
#define MSR_PLATFORM_INFO_CPUID_FAULT     BIT_ULL(MSR_PLATFORM_INFO_CPUID_FAULT_BIT)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
struct perf_guest_switch_msr {
	unsigned msr;
	u64 host, guest;
};

static inline struct perf_guest_switch_msr *perf_guest_get_msrs(int *nr)
{
	*nr = 0;
	return NULL;
}
#endif

#include <asm/perf_event.h>

#ifndef X86_PMC_MAX_GENERIC
#define X86_PMC_MAX_GENERIC				       32
#endif

#ifndef INTEL_PMC_MAX_GENERIC
#define INTEL_PMC_MAX_GENERIC	X86_PMC_MAX_GENERIC
#endif

#ifndef X86_PMC_MAX_FIXED
#define X86_PMC_MAX_FIXED					3
#endif

#ifndef INTEL_PMC_MAX_FIXED
#define INTEL_PMC_MAX_FIXED	X86_PMC_MAX_FIXED
#endif

#ifndef INTEL_PMC_IDX_FIXED
#define INTEL_PMC_IDX_FIXED	X86_PMC_IDX_FIXED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
union kvm_cpuid10_eax {
	struct {
		unsigned int version_id:8;
		unsigned int num_counters:8;
		unsigned int bit_width:8;
		unsigned int mask_length:8;
	} split;
	unsigned int full;
};
#else /* >= 2.6.35 */
#define kvm_cpuid10_eax	cpuid10_eax
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
union kvm_cpuid10_edx {
	struct {
		unsigned int num_counters_fixed:5;
		unsigned int bit_width_fixed:8;
		unsigned int reserved:19;
	} split;
	unsigned int full;
};
#else /* >= 2.6.36 */
#define kvm_cpuid10_edx	cpuid10_edx
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,8) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) || \
     LINUX_VERSION_CODE < KERNEL_VERSION(3,0,23))
static inline int user_has_fpu(void)
{
	return current_thread_info()->status & TS_USEDFPU;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,10)
static inline void amd_pmu_enable_virt(void) { }
static inline void amd_pmu_disable_virt(void) { }
#endif

#ifndef ARCH_PERFMON_EVENTSEL_PIN_CONTROL
#define ARCH_PERFMON_EVENTSEL_PIN_CONTROL		(1ULL << 19)
#endif

#include <asm/pvclock-abi.h>

#ifndef PVCLOCK_GUEST_STOPPED
#define PVCLOCK_GUEST_STOPPED	 (1 << 1)
#endif
#ifndef PVCLOCK_COUNTS_FROM_ZERO
#define PVCLOCK_COUNTS_FROM_ZERO (1 << 2)
#endif

#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline unsigned long __fls(unsigned long word)
{
	asm("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return word;
}
#endif

#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define cmpxchg64(ptr, o, n)						\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	cmpxchg((ptr), (o), (n));					\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
static inline unsigned long get_debugctlmsr(void)
{
	unsigned long debugctlmsr = 0;

#ifndef CONFIG_X86_DEBUGCTLMSR
	if (boot_cpu_data.x86 < 6)
		return 0;
#endif
	rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctlmsr);

	return debugctlmsr;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline void update_debugctlmsr(unsigned long debugctlmsr)
{
#ifndef CONFIG_X86_DEBUGCTLMSR
	if (boot_cpu_data.x86 < 6)
		return;
#endif
	wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctlmsr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)

#ifndef __ASM_SEL_RAW
#ifdef CONFIG_X86_32
# define __ASM_SEL_RAW(a,b) __ASM_FORM_RAW(a)
#else
# define __ASM_SEL_RAW(a,b) __ASM_FORM_RAW(b)
#endif
#endif

#ifndef __ASM_FORM_RAW
# define __ASM_FORM_RAW(x)     #x
#endif

#undef __ASM_REG
#define __ASM_REG(reg)	__ASM_SEL_RAW(e##reg, r##reg)

#undef _ASM_AX
#define _ASM_AX		__ASM_REG(ax)

#undef _ASM_BX
#define _ASM_BX		__ASM_REG(bx)

#undef _ASM_CX
#define _ASM_CX		__ASM_REG(cx)

#undef _ASM_DX
#define _ASM_DX		__ASM_REG(dx)

#undef _ASM_SP
#define _ASM_SP		__ASM_REG(sp)

#undef _ASM_BP
#define _ASM_BP		__ASM_REG(bp)

#undef _ASM_SI
#define _ASM_SI		__ASM_REG(si)

#undef _ASM_DI
#define _ASM_DI		__ASM_REG(di)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define __kernel_fpu_begin()	unlazy_fpu(current)
#define __kernel_fpu_end()	do { } while (0)
#endif

#ifndef MSR_IA32_TSC_ADJUST
#define MSR_IA32_TSC_ADJUST             0x0000003b
#endif

#ifndef X86_EFLAGS_FIXED
#define X86_EFLAGS_FIXED		0x00000002
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define POSTED_INTR_VECTOR		0xf2
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#define VFIO_DMA_CC_IOMMU		4
static inline void cpu_notifier_register_begin(void) {}
static inline void cpu_notifier_register_done(void) {}
static inline int __register_hotcpu_notifier(struct notifier_block *nb)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
#define kvm_cpu_has_xsaves	0
#else /* >= 3.17 */
#define kvm_cpu_has_xsaves	cpu_has_xsaves
#endif /* >= 3.17 */

#ifndef MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS
#define MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS (1ULL << 29)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#ifdef CONFIG_X86_64
typedef struct gate_struct gate_desc;
#else
typedef struct desc_struct gate_desc;
#endif
#endif /* < 2.6.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#ifdef CONFIG_X86_64
#define gate_offset(g) ((g).offset_low | ((unsigned long)(g).offset_middle << 16) | ((unsigned long)(g).offset_high << 32))
#else
#define gate_offset(g) (((g).b & 0xffff0000) | ((g).a & 0x0000ffff))
#endif
#endif /* < 2.6.28 */

#ifndef HSW_IN_TX
#define HSW_IN_TX			0
#define HSW_IN_TX_CHECKPOINTED		0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#define __cm_idx2pte(i)                                        \
       ((((i) & 4) << (_PAGE_BIT_PAT - 2)) |           \
        (((i) & 2) << (_PAGE_BIT_PCD - 1)) |           \
        (((i) & 1) << _PAGE_BIT_PWT))
#endif

#ifndef X86_EFLAGS_AC_BIT
#define X86_EFLAGS_AC_BIT	18 /* Alignment Check/Access Control */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
static inline unsigned long __read_cr4(void)
{
	return read_cr4();
}

static inline unsigned long cr4_read_shadow(void)
{
	return read_cr4();
}

static inline void cr4_set_bits(unsigned long bits)
{
	write_cr4(read_cr4() | bits);
}

static inline void cr4_clear_bits(unsigned long bits)
{
	write_cr4(read_cr4() & ~bits);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
static inline bool kvm_fpregs_active(void)
{
	return user_has_fpu();
}

static inline void copy_fpregs_to_fpstate(struct kvm_compat_fpu *fpu)
{
	kvm_fpu_save_init(fpu);
}

static inline void fpu__activate_curr(struct kvm_compat_fpu *fpu)
{
	struct task_struct *tsk =
		container_of(fpu, struct task_struct, thread.fpu);
	WARN_ON(!tsk_used_math(tsk) && init_fpu(tsk));
}

static inline void kvm_fpstate_init(struct kvm_compat_fpu *fpu)
{
	if (WARN_ON(kvm_fpu_alloc(fpu)))
		return;
	kvm_fpu_finit(fpu);
}
#else
static inline void kvm_fpu_free(struct kvm_compat_fpu *fpu)
{
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
enum irq_remap_cap {
	IRQ_POSTING_CAP = 0,
};

struct vcpu_data {
	u64 pi_desc_addr;	/* Physical address of PI Descriptor */
	u32 vector;		/* Guest vector of the interrupt */
};

static inline bool irq_remapping_cap(enum irq_remap_cap cap)
{
	return false;
}

static inline int irq_set_vcpu_affinity(unsigned int irq, void *vcpu_info)
{
	return -ENOSYS;
}

#define POSTED_INTR_WAKEUP_VECTOR	0xf1

static inline void kvm_set_posted_intr_wakeup_handler(void (*handler)(void)) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
static inline unsigned long long rdtsc(void)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));
	return EAX_EDX_VAL(val, low, high);
}

static inline unsigned long long rdtsc_ordered(void)
{
	smp_mb();
	return rdtsc();
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
static inline unsigned int x86_family(unsigned int sig)
{
	unsigned int x86;

	x86 = (sig >> 8) & 0xf;

	if (x86 == 0xf)
		x86 += (sig >> 20) & 0xff;

	return x86;
}

static inline unsigned int x86_model(unsigned int sig)
{
	unsigned int fam, model;

	fam = x86_family(sig);

	model = (sig >> 4) & 0xf;

	if (fam >= 0x6)
		model += ((sig >> 16) & 0xf) << 4;

	return model;
}

static inline unsigned int x86_stepping(unsigned int sig)
{
	return sig & 0xf;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
static inline u32 __read_pkru(void) { return 0; }
static inline void __write_pkru(u32 x) { }
static inline u32 read_pkru(void) { return 0; }
static inline void write_pkru(u32 x) { }
static inline u16 pte_flags_pkey(unsigned long pte_flags) { return 0; }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
enum cpuid_leafs
{
        CPUID_1_EDX             = 0,
        CPUID_8000_0001_EDX,
        CPUID_8086_0001_EDX,
        CPUID_LNX_1,
        CPUID_1_ECX,
        CPUID_C000_0001_EDX,
        CPUID_8000_0001_ECX,
        CPUID_LNX_2,
        CPUID_LNX_3,
        CPUID_7_0_EBX,
        CPUID_D_1_EAX,
        CPUID_F_0_EDX,
        CPUID_F_1_EDX,
        CPUID_8000_0008_EBX,
        CPUID_6_EAX,
        CPUID_8000_000A_EDX,
        CPUID_7_ECX,
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#define gsbase gs
#endif

#include <asm/pvclock.h>

static __always_inline
u64 kvm___pvclock_read_cycles(const struct pvclock_vcpu_time_info *src,
			      u64 tsc)
{
        u64 delta = tsc - src->tsc_timestamp;
        u64 offset = pvclock_scale_delta(delta, src->tsc_to_system_mul,
                                             src->tsc_shift);
        return src->system_time + offset;
}
#else
#define kvm___pvclock_read_cycles __pvclock_read_cycles
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
struct amd_iommu_pi_data {
        u32 ga_tag;
        u32 prev_ga_tag;
        u64 base;
        bool is_guest_mode;
        struct vcpu_data *vcpu_data;
        void *ir_data;
};

static inline int
amd_iommu_register_ga_log_notifier(int (*notifier)(u32))
{
	        return 0;
}

static inline int
amd_iommu_update_ga(int cpu, bool is_run, void *data)
{
	        return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
enum cpuid_regs_idx {
        CPUID_EAX = 0,
        CPUID_EBX,
        CPUID_ECX,
        CPUID_EDX,
};

static inline int get_scattered_cpuid_leaf(int eax, int ecx, enum cpuid_regs_idx reg)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
extern DEFINE_PER_CPU(struct kvm_desc_ptr, kvm_host_gdt);

static inline struct kvm_desc_struct *get_current_gdt_rw(void)
{
	struct kvm_desc_ptr *gdt_descr = this_cpu_ptr(&kvm_host_gdt);
	return (struct kvm_desc_struct *)gdt_descr->address;
}

static inline struct kvm_desc_struct *get_current_gdt_ro(void)
{
	struct kvm_desc_ptr *gdt_descr = this_cpu_ptr(&kvm_host_gdt);
	return (struct kvm_desc_struct *)gdt_descr->address;
}

static inline unsigned long get_current_gdt_ro_vaddr(void)
{
	struct kvm_desc_ptr *gdt_descr = this_cpu_ptr(&kvm_host_gdt);
	return gdt_descr->address;
}

extern void load_fixmap_gdt(int processor_id);
extern void kvm_do_store_gdt(void);
#else
static inline void kvm_do_store_gdt(void) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
static inline unsigned long kvm_read_tr_base(void)
{
	struct kvm_desc_struct *descs = get_current_gdt_ro();
	struct kvm_desc_struct *d = &descs[GDT_ENTRY_TSS];
	unsigned long v;

	v = kvm_get_desc_base(d);
#ifdef CONFIG_X86_64
	v |= ((unsigned long)((struct kvm_ldttss_desc64 *)d)->base3) << 32;
#endif
	return v;
}
#else
static inline unsigned long kvm_read_tr_base(void)
{
        return (unsigned long) this_cpu_ptr(&cpu_tss);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
/* BUILD_BUG_ON in vmx.c is unnecessary if TR is always force-reloaded.  */
#undef IO_BITMAP_OFFSET
#define IO_BITMAP_OFFSET 0x68

static inline void kvm_invalidate_tss_limit(void)
{
	/*
	 * VT restores TR but not its size.  Useless.
	 */
	struct kvm_desc_struct *descs;

	descs = get_current_gdt_rw();
	descs[GDT_ENTRY_TSS].type = 9; /* available TSS */
	load_TR_desc();
}
#else
#define kvm_invalidate_tss_limit invalidate_tss_limit
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
static inline unsigned long __read_cr3(void)
{
	return read_cr3();
}

static inline unsigned long __get_current_cr3_fast(void)
{
	return read_cr3();
}
#endif
