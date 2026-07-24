#pragma once

#include <stdint.h>

#include <initgraph.hpp>
#include <thor-internal/security.hpp>

namespace thor::x86_security {

enum class CpuVendor : uint8_t {
	unknown,
	intel,
	amd
};

struct CpuidRegisters {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
};

// This contains only inputs consulted by the foundation. It is deliberately
// per-CPU: a BSP observation is not evidence that another CPU has a feature.
struct CapabilitySnapshot {
	bool observed{false};
	CpuVendor vendor{CpuVendor::unknown};
	uint32_t family{0};
	uint32_t model{0};
	uint32_t stepping{0};
	bool hypervisorPresent{false};

	CpuidRegisters basicLeaf0{};
	CpuidRegisters featureLeaf1{};
	CpuidRegisters structuredLeaf7_0{};
	CpuidRegisters structuredLeaf7_1{};
	CpuidRegisters extendedLeaf0{};
	CpuidRegisters extendedLeaf1{};
	CpuidRegisters extendedLeaf8{};
	CpuidRegisters hypervisorLeaf0{};

	// Intel enumerates IBRS and IBPB together in CPUID.07H.00H:EDX[26].
	// AMD enumerates them independently in CPUID.80000008H:EBX.
	bool haveIbrs{false};
	bool haveIbpb{false};
	bool haveStibp{false};
	bool haveSsbd{false};
	bool haveMdClear{false};
	bool haveArchCapabilities{false};
	bool haveVmx{false};
	bool haveSvm{false};

	// IA32_ARCH_CAPABILITIES is read only when CPUID authorizes that exact MSR.
	bool archCapabilitiesKnown{false};
	uint64_t archCapabilities{0};

	// Microcode discovery is intentionally deferred. No uncertain MSR is probed.
	bool microcodeRevisionKnown{false};
	uint64_t microcodeRevision{0};

	// Reconciliation marks CPUs that can participate in a common set for the
	// controls represented above. A false value never means the CPU is offline.
	bool eligibleForSpeculationControls{false};
	const security::Evidence *capabilityEvidence{nullptr};
};

// Must run locally before VMXON/SVME and before this CPU becomes schedulable.
void discoverThisCpuCapabilities();

// Recompute the compatible set after local discovery. The result is incomplete
// until every configured CPU has recorded a snapshot.
void reconcileCpuCapabilities();
bool cpuCapabilitySetFinalized();

const security::Evidence &intelCpuidEvidence();
const security::Evidence &amdCpuidEvidence();

initgraph::Stage *getSecurityPolicyFrozenStage();

// Fixed transition-hook phases. Production hooks are compiler barriers only;
// they never dispatch dynamically and never select a mitigation action.
//
// rawUserEntry: legacy IDT/SYSCALL or FRED ring-3 entry, before untrusted state
//   is consumed beyond the architectural entry frame. Stack/address-space may
//   still be user controlled; GS/per-CPU access is not assumed.
// trustedEntryState: after the entry path established its kernel frame and
//   stack. Interrupt state and NMI nesting remain owned by that path.
// userReturnPreparation: registers and return state are prepared while the
//   kernel stack and kernel GS are still valid.
// finalUserReturn: immediately before IRET/SYSRET/ERETU after all state needed
//   by the return instruction is established.
// contextChange: scheduler/executor handoff; not every context switch is a
//   security-domain change. Future domain assignment calls this phase only when
//   the identities differ.
// preVmEntry/postVmExit: fixed assembly sites immediately around VMLAUNCH,
//   VMRESUME, and VMRUN. postVmExit precedes generic VM-exit processing.
// preIdle/postIdle: around HLT; postIdle runs after an interrupt returns from
//   HLT, before the idle loop halts again.
// nmiEntry/nmiReturn: NMI paths are counted independently in test builds,
//   including nested NMIs; they remain action-free in production.
enum class TransitionHook : uint8_t {
	rawUserEntry,
	trustedEntryState,
	userReturnPreparation,
	finalUserReturn,
	contextChange,
	preVmEntry,
	postVmExit,
	preIdle,
	postIdle,
	nmiEntry,
	nmiReturn,
	numHooks
};

#if defined(THOR_SECURITY_TEST_HOOKS)
// Test-only instrumentation is deliberately per CPU and does not dispatch
// through a callback. Assembly hooks increment the matching GS-relative slot;
// C++ hooks use this direct helper.
void transitionHook(TransitionHook hook);
uint64_t transitionHookCount(TransitionHook hook);
#else
inline void transitionHook(TransitionHook) {
	asm volatile ("" : : : "memory");
}
#endif

} // namespace thor::x86_security
