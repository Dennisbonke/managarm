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

} // namespace thor::x86_security
