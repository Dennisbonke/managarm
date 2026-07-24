#pragma once

#include <thor-internal/arch/asm.h>
#include <thor-internal/arch/speculation-security.hpp>
#include <thor-internal/kernel-stack.hpp>
#include <x86/tss.hpp>

namespace thor {

struct Executor;
struct IseqContext;
struct UserAccessRegion;

// Note: This struct is accessed from assembly.
struct AssemblyCpuData {
	AssemblyCpuData *selfPointer;
	Executor *activeExecutor{nullptr};
	void *syscallStack;
	IseqContext *iseqPtr{nullptr};
#if defined(THOR_SECURITY_TEST_HOOKS)
	// Test builds count fixed security phases through GS-relative assembly
	// increments. Keep this immediately after the fields with pre-existing
	// assembly offsets and keep the matching values in asm.h in sync.
	uint64_t securityTransitionCounters[
			static_cast<size_t>(x86_security::TransitionHook::numHooks)]{};
#endif
};

static_assert(offsetof(AssemblyCpuData, selfPointer) == THOR_GS_SELF);
static_assert(offsetof(AssemblyCpuData, activeExecutor) == THOR_GS_EXECUTOR);
static_assert(offsetof(AssemblyCpuData, syscallStack) == THOR_GS_SYSCALL_STACK);
static_assert(offsetof(AssemblyCpuData, iseqPtr) == THOR_GS_ISEQ_PTR);
#if defined(THOR_SECURITY_TEST_HOOKS)
static_assert(offsetof(AssemblyCpuData, securityTransitionCounters)
		== THOR_GS_SECURITY_TRANSITION_COUNTERS);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::rawUserEntry) * sizeof(uint64_t)
		== THOR_GS_SECURITY_RAW_USER_ENTRY_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::trustedEntryState) * sizeof(uint64_t)
		== THOR_GS_SECURITY_TRUSTED_ENTRY_STATE_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::userReturnPreparation) * sizeof(uint64_t)
		== THOR_GS_SECURITY_USER_RETURN_PREPARATION_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::finalUserReturn) * sizeof(uint64_t)
		== THOR_GS_SECURITY_FINAL_USER_RETURN_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::contextChange) * sizeof(uint64_t)
		== THOR_GS_SECURITY_CONTEXT_CHANGE_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::preVmEntry) * sizeof(uint64_t)
		== THOR_GS_SECURITY_PRE_VM_ENTRY_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::postVmExit) * sizeof(uint64_t)
		== THOR_GS_SECURITY_POST_VM_EXIT_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::preIdle) * sizeof(uint64_t)
		== THOR_GS_SECURITY_PRE_IDLE_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::postIdle) * sizeof(uint64_t)
		== THOR_GS_SECURITY_POST_IDLE_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::nmiEntry) * sizeof(uint64_t)
		== THOR_GS_SECURITY_NMI_ENTRY_COUNT);
static_assert(THOR_GS_SECURITY_TRANSITION_COUNTERS
		+ static_cast<size_t>(x86_security::TransitionHook::nmiReturn) * sizeof(uint64_t)
		== THOR_GS_SECURITY_NMI_RETURN_COUNT);
#endif

struct Thread;

struct PlatformCpuData : public AssemblyCpuData {
	PlatformCpuData();

	int localApicId;

	UniqueKernelStack dfStack;
	UniqueKernelStack nmiStack;

	bool havePcids = false;
	bool haveSmap = false;
	bool haveVirtualization = false;
	x86_security::CapabilitySnapshot securityCapabilities;
};

// Get a pointer to this CPU's PlatformCpuData instance.
inline PlatformCpuData *getPlatformCpuData() {
	AssemblyCpuData *cpu_data;
	asm volatile ("mov %%gs:0, %0" : "=r"(cpu_data));
	return static_cast<PlatformCpuData *>(cpu_data);
}

} // namespace thor
