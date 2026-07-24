#include <thor-internal/arch/speculation-security.hpp>

#include <thor-internal/cpu-data.hpp>
#include <thor-internal/debug.hpp>
#include <thor-internal/main.hpp>
#include <x86/machine.hpp>

namespace thor::x86_security {

namespace {

constexpr security::Evidence intelCpuid{
		"intel.sdm.cpuid.092",
		security::Vendor::intel,
		"325462",
		"Intel 64 and IA-32 Architectures Software Developer's Manual",
		"092 (June 2026)",
		"CPUID—CPU Identification; IA32_ARCH_CAPABILITIES",
		"",
		"",
		"CPUID leaf 7 EDX bits authorize the corresponding architectural "
		"speculation-control and IA32_ARCH_CAPABILITIES accesses."
};

constexpr security::Evidence amdCpuid{
		"amd.apm.cpuid.3.44",
		security::Vendor::amd,
		"24593",
		"AMD64 Architecture Programmer's Manual, Volume 2: System Programming",
		"3.44 (March 2026)",
		"System Resources; Speculation Control",
		"",
		"",
		"CPUID Fn8000_0008 EBX bits independently authorize AMD IBPB, IBRS, "
		"STIBP, and SSBD controls; they do not establish vulnerability applicability."
};

constexpr uint32_t bit(unsigned int n) {
	return uint32_t{1} << n;
}

CpuVendor decodeVendor(const CpuidRegisters &leaf) {
	// CPUID vendor strings are EBX, EDX, ECX in that order.
	if(leaf.ebx == 0x756e6547 && leaf.edx == 0x49656e69 && leaf.ecx == 0x6c65746e)
		return CpuVendor::intel; // GenuineIntel
	if(leaf.ebx == 0x68747541 && leaf.edx == 0x69746e65 && leaf.ecx == 0x444d4163)
		return CpuVendor::amd; // AuthenticAMD
	return CpuVendor::unknown;
}

CpuidRegisters cpuid(uint32_t leaf, uint32_t subleaf = 0) {
	auto registers = common::x86::cpuid(leaf, subleaf);
	return {registers[0], registers[1], registers[2], registers[3]};
}

constexpr void decodeSpeculationCapabilities(CapabilitySnapshot &snapshot) {
	if(snapshot.vendor == CpuVendor::amd) {
		// AMD APM volume 2, "Speculation Control": Fn8000_0008 EBX
		// enumerates IBPB, IBRS, STIBP, and SSBD independently.
		snapshot.haveIbpb = snapshot.extendedLeaf8.ebx & bit(12);
		snapshot.haveIbrs = snapshot.extendedLeaf8.ebx & bit(14);
		snapshot.haveStibp = snapshot.extendedLeaf8.ebx & bit(15);
		snapshot.haveSsbd = snapshot.extendedLeaf8.ebx & bit(24);
	} else {
		auto leaf7Edx = snapshot.structuredLeaf7_0.edx;
		snapshot.haveIbrs = leaf7Edx & bit(26);
		snapshot.haveIbpb = leaf7Edx & bit(26);
		snapshot.haveStibp = leaf7Edx & bit(27);
		snapshot.haveSsbd = leaf7Edx & bit(31);
	}

	snapshot.haveMdClear = snapshot.structuredLeaf7_0.edx & bit(10);
	snapshot.haveArchCapabilities = snapshot.structuredLeaf7_0.edx & bit(29);
}

constexpr bool controlsCompatible(const CapabilitySnapshot &a, const CapabilitySnapshot &b) {
	return a.vendor == b.vendor
			&& a.hypervisorPresent == b.hypervisorPresent
			&& a.haveIbrs == b.haveIbrs
			&& a.haveIbpb == b.haveIbpb
			&& a.haveStibp == b.haveStibp
			&& a.haveSsbd == b.haveSsbd
			&& a.haveMdClear == b.haveMdClear
			&& a.haveArchCapabilities == b.haveArchCapabilities
			&& a.archCapabilitiesKnown == b.archCapabilitiesKnown
			&& (!a.archCapabilitiesKnown || a.archCapabilities == b.archCapabilities);
}

constexpr bool testAmdSpeculationCapabilityDecoding() {
	CapabilitySnapshot snapshot{
		.vendor = CpuVendor::amd,
		.extendedLeaf8 = {.ebx = bit(12) | bit(15) | bit(24)}
	};
	decodeSpeculationCapabilities(snapshot);
	return snapshot.haveIbpb && !snapshot.haveIbrs
			&& snapshot.haveStibp && snapshot.haveSsbd;
}
static_assert(testAmdSpeculationCapabilityDecoding());

constexpr CapabilitySnapshot compatibleSynthetic{
	.observed = true,
	.vendor = CpuVendor::intel,
	.haveIbrs = true,
	.haveIbpb = true,
	.haveArchCapabilities = true,
	.archCapabilitiesKnown = true,
	.archCapabilities = 1
};
constexpr CapabilitySnapshot incompatibleSynthetic{
	.observed = true,
	.vendor = CpuVendor::intel,
	.haveIbrs = true,
	.haveIbpb = true,
	.haveArchCapabilities = true,
	.archCapabilitiesKnown = true,
	.archCapabilities = 2
};
static_assert(controlsCompatible(compatibleSynthetic, compatibleSynthetic));
static_assert(!controlsCompatible(compatibleSynthetic, incompatibleSynthetic));

} // namespace

const security::Evidence &intelCpuidEvidence() {
	return intelCpuid;
}

const security::Evidence &amdCpuidEvidence() {
	return amdCpuid;
}

initgraph::Stage *getSecurityPolicyFrozenStage() {
	static initgraph::Stage stage{&globalInitEngine, "x86.security-policy-frozen"};
	return &stage;
}

static initgraph::Task freezeSecurityPolicyTask{&globalInitEngine, "x86.freeze-security-policy",
		initgraph::Entails{getSecurityPolicyFrozenStage()}, [] {
		// thorMain() initializes the command line before the init graph runs.
		auto &state = security::architectureState();
		auto error = security::parsePolicy(getKernelCmdline(), state.policy());
		if(error != security::PolicyParseError::success)
			panicLogger() << "thor: invalid speculation_security command-line policy: "
					<< static_cast<unsigned int>(error) << frg::endlog;
		state.freezePolicy();
	}};

void discoverThisCpuCapabilities() {
	auto &snapshot = getCpuData()->securityCapabilities;

	snapshot.basicLeaf0 = cpuid(0);
	snapshot.vendor = decodeVendor(snapshot.basicLeaf0);
	if(snapshot.basicLeaf0.eax >= 1)
		snapshot.featureLeaf1 = cpuid(1);
	if(snapshot.basicLeaf0.eax >= 7) {
		snapshot.structuredLeaf7_0 = cpuid(7, 0);
		if(snapshot.structuredLeaf7_0.eax >= 1)
			snapshot.structuredLeaf7_1 = cpuid(7, 1);
	}

	snapshot.extendedLeaf0 = cpuid(0x80000000);
	if(snapshot.extendedLeaf0.eax >= 0x80000001)
		snapshot.extendedLeaf1 = cpuid(0x80000001);
	if(snapshot.extendedLeaf0.eax >= 0x80000008)
		snapshot.extendedLeaf8 = cpuid(0x80000008);

	snapshot.hypervisorPresent = snapshot.featureLeaf1.ecx & bit(31);
	if(snapshot.hypervisorPresent)
		snapshot.hypervisorLeaf0 = cpuid(0x40000000);

	auto signature = snapshot.featureLeaf1.eax;
	auto baseFamily = (signature >> 8) & 0xF;
	auto baseModel = (signature >> 4) & 0xF;
	snapshot.family = baseFamily == 0xF ? baseFamily + ((signature >> 20) & 0xFF) : baseFamily;
	snapshot.model = (baseFamily == 0x6 || baseFamily == 0xF)
			? baseModel | ((signature >> 12) & 0xF0) : baseModel;
	snapshot.stepping = signature & 0xF;

	snapshot.haveVmx = snapshot.featureLeaf1.ecx & bit(5);
	snapshot.haveSvm = snapshot.extendedLeaf1.ecx & bit(2);
	decodeSpeculationCapabilities(snapshot);

	if(snapshot.vendor == CpuVendor::intel) {
		snapshot.capabilityEvidence = &intelCpuid;
		if(snapshot.haveArchCapabilities) {
			// CPUID.07H.00H:EDX[29] is the exact authorization predicate.
			snapshot.archCapabilities = common::x86::rdmsr(0x10A);
			snapshot.archCapabilitiesKnown = true;
		}
	} else if(snapshot.vendor == CpuVendor::amd) {
		snapshot.capabilityEvidence = &amdCpuid;
	}

	// Do not infer an AMD or virtualized microcode revision and do not issue an
	// uncertain MSR read. A later, evidence-backed microcode project owns that.
	snapshot.observed = true;

	debugLogger() << "thor: security CPU " << getCpuData()->cpuIndex
			<< " observed family " << snapshot.family << " model " << snapshot.model
			<< " stepping " << snapshot.stepping
			<< "; observed microcode revision unknown" << frg::endlog;
}

void reconcileCpuCapabilities() {
	CapabilitySnapshot *baseline = nullptr;
	size_t observed = 0;
	bool mismatch = false;

	for(size_t i = 0; i < getCpuCount(); ++i) {
		auto &snapshot = getCpuData(i)->securityCapabilities;
		if(!snapshot.observed)
			continue;
		++observed;
		if(!baseline)
			baseline = &snapshot;
	}

	if(!baseline)
		return;
	for(size_t i = 0; i < getCpuCount(); ++i) {
		auto &snapshot = getCpuData(i)->securityCapabilities;
		if(!snapshot.observed)
			continue;
		snapshot.eligibleForSpeculationControls = controlsCompatible(*baseline, snapshot);
		mismatch |= !snapshot.eligibleForSpeculationControls;
	}

	if(mismatch)
		infoLogger() << "thor: security capability mismatch; incompatible CPUs are excluded "
				"from speculation-control eligible sets" << frg::endlog;
	if(observed == getCpuCount())
		debugLogger() << "thor: security capability CPU-set reconciliation complete" << frg::endlog;
}

bool cpuCapabilitySetFinalized() {
	for(size_t i = 0; i < getCpuCount(); ++i)
		if(!getCpuData(i)->securityCapabilities.observed)
			return false;
	return true;
}

} // namespace thor::x86_security
