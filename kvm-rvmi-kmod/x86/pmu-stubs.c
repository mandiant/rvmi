/*
 * Kernel-based Virtual Machine -- Performance Monitoring Unit support
 *
 * Compatibility stubs
 *
 * Copyright 2012 Siemens AG.
 *
 * Authors:
 *   Jan Kiszka   <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

bool kvm_pmu_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	return false;
}

int kvm_pmu_read_pmc(struct kvm_vcpu *vcpu, unsigned pmc, u64 *data)
{
	return 1;
}

int kvm_pmu_get_msr(struct kvm_vcpu *vcpu, u32 index, u64 *data)
{
	BUG();
	return -1;
}

int kvm_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	BUG();
	return -1;
}

void kvm_deliver_pmi(struct kvm_vcpu *vcpu)
{
	BUG();
}

void kvm_pmu_cpuid_update(struct kvm_vcpu *vcpu)
{
}

void kvm_pmu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;

	memset(pmu, 0, sizeof(*pmu));
}

void kvm_pmu_reset(struct kvm_vcpu *vcpu)
{
}

void kvm_pmu_destroy(struct kvm_vcpu *vcpu)
{
}

void kvm_handle_pmu_event(struct kvm_vcpu *vcpu)
{
	BUG();
}
