#include <thor-internal/arch/speculation-security.hpp>

#include <thor-internal/arch/speculation-mechanisms.hpp>
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

constexpr security::Evidence ibpbMechanismEvidence{
		"x86.ibpb.mechanism.2026",
		security::Vendor::unknown,
		"Intel 325462; AMD 24593",
		"x86 IBPB mechanism authorization",
		"Intel 092 (June 2026); AMD 3.44 (March 2026)",
		"Intel CPUID.07H.0:EDX[26] and IA32_PRED_CMD; AMD Speculation Control",
		"",
		"",
		"CPUID authorizes only the local predictor-barrier mechanism; applicability "
		"is established by the separate, vendor-backed registry entries below."
};

constexpr security::Evidence intelBranchTargetInjectionEvidence{
		"intel.bti.affected-processors.2026-07-25",
		security::Vendor::intel,
		"Intel-affected-processor-list b8945071bbe3688f8fee344e78a01b33fd34f46d",
		"Intel Affected Processor List",
		"snapshot 2026-07-25; SHA-256 e8664f58468c5839151025f4afcabbb964c7ad427345ee3c9ca74c302658413f",
		"Branch Target Injection (Spectre v2) column; CPUID Family_Model and Stepping",
		"CVE-2017-5715 / INTEL-SA-00088",
		"e8664f58468c5839151025f4afcabbb964c7ad427345ee3c9ca74c302658413f",
		"Matches only the exact Intel family 06 model/stepping rows whose Branch Target "
		"Injection column requires a mitigation. A physical product table is never used "
		"when CPUID reports a hypervisor."
};

constexpr security::Evidence amdBranchTargetInjectionEvidence{
		"amd.bti.affected-products.2022",
		security::Vendor::amd,
		"AMD-SB-1036; Technical Guidance for Mitigating Branch Type Confusion",
		"LFENCE/JMP Mitigation Update for CVE-2017-5715",
		"AMD-SB-1036, 2022-03-08; Branch Type Confusion guidance, 2022",
		"Affected Products; BTC-IND family/model table",
		"CVE-2017-5715 / CVE-2021-26401",
		"",
		"Maps AMD's affected Zen product generations to the published Family 17h and "
		"Family 19h model ranges. A physical product table is never used when CPUID "
		"reports a hypervisor."
};

constexpr security::Evidence ibpbApplicabilityAggregateEvidence{
		"x86.ibpb.applicability.aggregate.2026",
		security::Vendor::unknown,
		"Intel-affected-processor-list; AMD-SB-1036",
		"x86 IBPB applicability aggregate",
		"2026-07-25",
		"Per-CPU vendor applicability registry aggregation",
		"CVE-2017-5715",
		"",
		"The boundary decision aggregates the immutable per-CPU Intel and AMD evidence "
		"records; any unknown CPU keeps the aggregate applicability unknown."
};

constexpr const security::Evidence *x86EvidenceEntries[] = {
		&intelCpuid,
		&amdCpuid,
		&ibpbMechanismEvidence,
		&intelBranchTargetInjectionEvidence,
		&amdBranchTargetInjectionEvidence,
		&ibpbApplicabilityAggregateEvidence
};
constexpr security::EvidenceRegistry x86EvidenceRegistry{
		x86EvidenceEntries, sizeof(x86EvidenceEntries) / sizeof(x86EvidenceEntries[0])
};
static_assert(x86EvidenceRegistry.count == 6);
static_assert(x86EvidenceRegistry.at(0) == &intelCpuid);
static_assert(x86EvidenceRegistry.at(1) == &amdCpuid);
static_assert(x86EvidenceRegistry.at(2) == &ibpbMechanismEvidence);
static_assert(x86EvidenceRegistry.at(3) == &intelBranchTargetInjectionEvidence);
static_assert(x86EvidenceRegistry.at(4) == &amdBranchTargetInjectionEvidence);
static_assert(x86EvidenceRegistry.at(5) == &ibpbApplicabilityAggregateEvidence);

constexpr uint32_t bit(unsigned int n) {
	return uint32_t{1} << n;
}

struct IntelAffectedStepping {
	uint32_t model;
	uint16_t steppingMask;
};

// Intel's official machine-readable affected-processor snapshot contains these
// exact Family 06 model/stepping rows in its Spectre-v2 column. Do not turn a
// range into an inference: a bit is present only when the published row is.
constexpr IntelAffectedStepping intelAffectedSteppings[] = {
		{0x3f, 0x0014}, {0x4f, 0x0002}, {0x55, 0x0818}, {0x56, 0x0038},
		{0x5c, 0x0400}, {0x5e, 0x0008}, {0x5f, 0xffff}, {0x6a, 0x0040},
		{0x6c, 0xffff}, {0x7a, 0x0100}, {0x7e, 0x0020}, {0x86, 0x00a0},
		{0x8c, 0x0006}, {0x8d, 0x0002}, {0x8e, 0x1e00}, {0x8f, 0x01e0},
		{0x96, 0xffff}, {0x97, 0x0024}, {0x9a, 0x0018}, {0x9c, 0xffff},
		{0x9e, 0x3600}, {0xa5, 0x002c}, {0xa6, 0x0003}, {0xa7, 0x0002},
		{0xaa, 0x0002}, {0xad, 0x0002}, {0xae, 0x0002}, {0xaf, 0x0008},
		{0xb5, 0x0001}, {0xb6, 0x0010}, {0xb7, 0x0002}, {0xba, 0x010c},
		{0xbd, 0x0002}, {0xbe, 0x0001}, {0xbf, 0x0024}, {0xc5, 0x0004},
		{0xc6, 0x0004}, {0xcc, 0x000c}, {0xcf, 0x0004}, {0xd5, 0x0002},
		{0xd7, 0x0001}
};

constexpr bool isIntelAffectedByBranchTargetInjection(const CapabilitySnapshot &snapshot) {
	if(snapshot.vendor != CpuVendor::intel || snapshot.family != 0x6 || snapshot.stepping >= 16)
		return false;
	for(auto entry : intelAffectedSteppings)
		if(entry.model == snapshot.model && (entry.steppingMask & (uint16_t{1} << snapshot.stepping)))
			return true;
	return false;
}

#warning "TODO(security): Audit AMD IBPB applicability against a CPUID-precise vendor source"
// TODO(security): The current AMD Family 17h/19h ranges were derived by
// collapsing product lists and BTC guidance that cover different issues. In
// particular, the BTC guidance says Family 19h is not vulnerable to BTC while
// SB-1036 lists selected Family 19h products for its LFENCE/JMP issue; neither
// document classifies every Zen generation or Family 1Ah for this IBPB policy.
// Keep unknown rather than extending this mapping until a vendor-authoritative,
// CPUID family/model/stepping applicability source is incorporated.
constexpr bool isAmdAffectedByBranchTargetInjection(const CapabilitySnapshot &snapshot) {
	if(snapshot.vendor != CpuVendor::amd)
		return false;
	// AMD-SB-1036 identifies the affected EPYC/Ryzen generations. AMD's family
	// table maps those generations to these Family 17h and 19h model intervals.
	if(snapshot.family == 0x17)
		return snapshot.model <= 0x2f
				|| (snapshot.model >= 0x30 && snapshot.model <= 0x7f)
				|| (snapshot.model >= 0xa0 && snapshot.model <= 0xaf);
	return snapshot.family == 0x19;
}

constexpr void determineIbpbApplicability(CapabilitySnapshot &snapshot) {
	snapshot.ibpbApplicability = security::Applicability::unknown;
	snapshot.ibpbApplicabilityEvidence = nullptr;
	if(snapshot.hypervisorPresent)
		return;
	if(isIntelAffectedByBranchTargetInjection(snapshot)) {
		snapshot.ibpbApplicability = security::Applicability::affected;
		snapshot.ibpbApplicabilityEvidence = &intelBranchTargetInjectionEvidence;
	} else if(isAmdAffectedByBranchTargetInjection(snapshot)) {
		snapshot.ibpbApplicability = security::Applicability::affected;
		snapshot.ibpbApplicabilityEvidence = &amdBranchTargetInjectionEvidence;
	}
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

constexpr bool testIbpbApplicabilityRegistry() {
	CapabilitySnapshot intel{
		.vendor = CpuVendor::intel, .family = 0x6, .model = 0x55, .stepping = 0x4
	};
	determineIbpbApplicability(intel);
	if(intel.ibpbApplicability != security::Applicability::affected
			|| intel.ibpbApplicabilityEvidence != &intelBranchTargetInjectionEvidence)
		return false;

	CapabilitySnapshot intelUnlisted{
		.vendor = CpuVendor::intel, .family = 0x6, .model = 0x55, .stepping = 0x5
	};
	determineIbpbApplicability(intelUnlisted);
	if(intelUnlisted.ibpbApplicability != security::Applicability::unknown)
		return false;

	CapabilitySnapshot amd{
		.vendor = CpuVendor::amd, .family = 0x17, .model = 0x31
	};
	determineIbpbApplicability(amd);
	if(amd.ibpbApplicability != security::Applicability::affected
			|| amd.ibpbApplicabilityEvidence != &amdBranchTargetInjectionEvidence)
		return false;

	CapabilitySnapshot virtualized = intel;
	virtualized.hypervisorPresent = true;
	determineIbpbApplicability(virtualized);
	return virtualized.ibpbApplicability == security::Applicability::unknown
			&& !virtualized.ibpbApplicabilityEvidence;
}
static_assert(testIbpbApplicabilityRegistry());

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

constexpr CapabilitySnapshot unprivilegedSynthetic{.observed = true};
constexpr CapabilitySnapshot intelArchCapabilitiesSynthetic{
	.observed = true,
	.vendor = CpuVendor::intel,
	.haveIbrs = true,
	.haveIbpb = true,
	.haveMdClear = true,
	.haveArchCapabilities = true
};
constexpr CapabilitySnapshot amdArchCapabilitiesSynthetic{
	.observed = true,
	.vendor = CpuVendor::amd,
	.haveArchCapabilities = true
};
constexpr CapabilitySnapshot virtualizedSynthetic{
	.observed = true,
	.vendor = CpuVendor::intel,
	.hypervisorPresent = true,
	.haveIbrs = true,
	.haveIbpb = true
};
constexpr CapabilitySnapshot affectedIntelSynthetic{
	.observed = true,
	.vendor = CpuVendor::intel,
	.haveIbrs = true,
	.haveIbpb = true,
	.ibpbApplicability = security::Applicability::affected,
	.ibpbApplicabilityEvidence = &intelBranchTargetInjectionEvidence
};
constexpr CapabilitySnapshot notAffectedSynthetic{
	.observed = true,
	.vendor = CpuVendor::intel,
	.haveIbpb = true,
	.ibpbApplicability = security::Applicability::notAffected
};
static_assert(!canReadArchCapabilities(unprivilegedSynthetic));
static_assert(!canAccessSpeculationControl(unprivilegedSynthetic));
static_assert(!canIssuePredictorBarrier(unprivilegedSynthetic));
static_assert(!canClearCpuBuffers(unprivilegedSynthetic));
static_assert(canReadArchCapabilities(intelArchCapabilitiesSynthetic));
static_assert(canAccessSpeculationControl(intelArchCapabilitiesSynthetic));
static_assert(canWriteIbrs(intelArchCapabilitiesSynthetic));
static_assert(canIssuePredictorBarrier(intelArchCapabilitiesSynthetic));
static_assert(canClearCpuBuffers(intelArchCapabilitiesSynthetic));
static_assert(!canReadArchCapabilities(amdArchCapabilitiesSynthetic));
static_assert(canIssuePredictorBarrier(virtualizedSynthetic));
static_assert(!controlsCompatible(intelArchCapabilitiesSynthetic, virtualizedSynthetic));

constexpr security::TransitionDescriptor sameUserDomain{
		1, 1, security::TransitionScope::userProcess
};
constexpr security::TransitionDescriptor differentUserDomains{
		1, 2, security::TransitionScope::userProcess
};
constexpr security::TransitionDescriptor kernelToUser{
		security::kernelDomain, 1, security::TransitionScope::kernel
};
constexpr security::TransitionDescriptor kernelToKernel{
		security::kernelDomain, security::kernelDomain, security::TransitionScope::kernel
};
constexpr security::TransitionDescriptor vmTransition{1, 2, security::TransitionScope::vm};
constexpr security::TransitionDescriptor idleTransition{1, 2, security::TransitionScope::idle};
constexpr security::TransitionDescriptor nmiTransition{1, 2, security::TransitionScope::nmi};
static_assert(!security::isIbpbRelevantTransition(sameUserDomain));
static_assert(security::isIbpbRelevantTransition(differentUserDomains));
static_assert(!security::isIbpbRelevantTransition(kernelToUser));
static_assert(!security::isIbpbRelevantTransition(kernelToKernel));
static_assert(!security::isIbpbRelevantTransition(vmTransition));
static_assert(!security::isIbpbRelevantTransition(idleTransition));
static_assert(!security::isIbpbRelevantTransition(nmiTransition));
static_assert(classifyIbpbTransition(differentUserDomains,
		{security::MechanismRequest::automatic, security::PolicySource::defaultValue},
		intelArchCapabilitiesSynthetic)
			== IbpbTransitionOutcome::inactivePendingApplicabilityEvidence);
static_assert(classifyIbpbTransition(differentUserDomains,
		{security::MechanismRequest::automatic, security::PolicySource::defaultValue},
		affectedIntelSynthetic) == IbpbTransitionOutcome::invoked);
static_assert(classifyIbpbTransition(differentUserDomains,
		{security::MechanismRequest::automatic, security::PolicySource::defaultValue},
		notAffectedSynthetic) == IbpbTransitionOutcome::notAffectedOnCpu);
static_assert(classifyIbpbTransition(differentUserDomains,
		{security::MechanismRequest::disabled, security::PolicySource::commandLine},
		intelArchCapabilitiesSynthetic) == IbpbTransitionOutcome::disabledByPolicy);
static_assert(classifyIbpbTransition(differentUserDomains,
		{security::MechanismRequest::forced, security::PolicySource::commandLine},
		unprivilegedSynthetic) == IbpbTransitionOutcome::unavailableOnCpu);
static_assert(classifyIbpbTransition(differentUserDomains,
		{security::MechanismRequest::forced, security::PolicySource::commandLine},
		intelArchCapabilitiesSynthetic) == IbpbTransitionOutcome::invoked);

constexpr security::MitigationDecision ibpbRegistrationTestDecision(
		security::BoundaryPolicy boundaryPolicy) {
	return security::deriveDecision({security::Applicability::unknown,
		security::MechanismAvailability::available, security::Enforcement::enabled,
		{security::MechanismRequest::forced, security::PolicySource::commandLine},
		boundaryPolicy, &ibpbMechanismEvidence});
}

constexpr bool testIbpbDecisionRegistration() {
	security::ArchitectureState state;
	if(!state.registerMitigation(security::TrustBoundary::processToProcess,
				&ibpbRegistrationTestDecision))
		return false;
	state.freezePolicy();
	if(!state.publishDeferredBoundaryRecords() || !state.finalizeBoundaryRecords())
		return false;
	auto permissive = state.boundaryDecision(security::TrustBoundary::processToProcess);
	return permissive && permissive->result == security::Result::unknown
			&& permissive->reason == security::Reason::unknownApplicability;
}
static_assert(testIbpbDecisionRegistration());

constexpr bool testRequiredIbpbBoundaryUnavailable() {
	security::ArchitectureState state;
	if(!state.policy().setBoundary(security::TrustBoundary::processToProcess,
			{security::BoundaryRequirement::required, security::PolicySource::commandLine}))
		return false;
	if(!state.registerMitigation(security::TrustBoundary::processToProcess,
				&ibpbRegistrationTestDecision))
		return false;
	state.freezePolicy();
	if(!state.publishDeferredBoundaryRecords() || !state.finalizeBoundaryRecords())
		return false;
	auto decision = state.boundaryDecision(security::TrustBoundary::processToProcess);
	return decision && decision->result == security::Result::unavailable
			&& decision->reason == security::Reason::requiredBoundaryUnavailable
			&& !security::canActivateBoundary(*decision);
}
static_assert(testRequiredIbpbBoundaryUnavailable());

constexpr bool testIbpbPolicyFreeze() {
	IbpbPolicy policy;
	if(!policy.set({security::MechanismRequest::automatic,
			security::PolicySource::defaultValue}))
		return false;
	policy.freeze();
	return !policy.set({security::MechanismRequest::forced,
		security::PolicySource::commandLine});
}
static_assert(testIbpbPolicyFreeze());

} // namespace

const security::Evidence &intelCpuidEvidence() {
	return intelCpuid;
}

const security::Evidence &amdCpuidEvidence() {
	return amdCpuid;
}

const security::EvidenceRegistry &evidenceRegistry() {
	return x86EvidenceRegistry;
}

initgraph::Stage *getSecurityPolicyFrozenStage() {
	static initgraph::Stage stage{&globalInitEngine, "x86.security-policy-frozen"};
	return &stage;
}

IbpbPolicy &ibpbPolicy() {
	static IbpbPolicy policy;
	return policy;
}

security::PolicyParseError configureIbpbPolicy(frg::string_view commandLine,
		security::MitigationPolicy inherited) {
	auto &policy = ibpbPolicy();
	if(policy.frozen())
		return security::PolicyParseError::conflictingOption;
	constexpr char ibpb[] = "ibpb";
	auto configured = inherited;
	auto error = security::parseMitigationPolicy(commandLine,
			{ibpb, sizeof(ibpb) - 1}, configured);
	if(error != security::PolicyParseError::success)
		return error;
	return policy.set(configured) ? security::PolicyParseError::success
			: security::PolicyParseError::conflictingOption;
}

security::MitigationDecision ibpbMitigationDecision(security::BoundaryPolicy boundaryPolicy) {
	bool allAffectedAvailable = true;
	bool anyAffected = false;
	bool anyUnknown = getCpuCount() == 0;
	for(size_t i = 0; i < getCpuCount(); ++i) {
		auto &snapshot = getCpuData(i)->securityCapabilities;
		if(!snapshot.observed || snapshot.ibpbApplicability == security::Applicability::unknown) {
			anyUnknown = true;
			continue;
		}
		if(snapshot.ibpbApplicability == security::Applicability::affected) {
			anyAffected = true;
			allAffectedAvailable &= canIssuePredictorBarrier(snapshot);
		}
	}
	auto applicability = anyUnknown ? security::Applicability::unknown
			: anyAffected ? security::Applicability::affected : security::Applicability::notAffected;
	auto mechanism = allAffectedAvailable ? security::MechanismAvailability::available
			: security::MechanismAvailability::unavailable;
	auto policy = ibpbPolicy().policy();
	auto enforcement = policy.request == security::MechanismRequest::disabled
			? security::Enforcement::disabledByPolicy : security::Enforcement::notAttempted;
	return security::deriveDecision({applicability, mechanism, enforcement,
			policy, boundaryPolicy, &ibpbApplicabilityAggregateEvidence});
}

#if defined(THOR_SECURITY_TEST_HOOKS)
namespace {
PredictorBarrierInvoker predictorBarrierInvokerForTest{nullptr};
}

PredictorBarrierInvoker setPredictorBarrierInvokerForTest(PredictorBarrierInvoker invoker) {
	auto previous = predictorBarrierInvokerForTest;
	predictorBarrierInvokerForTest = invoker;
	return previous;
}

uint64_t ibpbAttemptCount() {
	return __atomic_load_n(&getCpuData()->securityIbpbAttemptCount, __ATOMIC_RELAXED);
}

uint64_t ibpbCompletedCount() {
	return __atomic_load_n(&getCpuData()->securityIbpbCompletedCount, __ATOMIC_RELAXED);
}
#endif

void handleIbpbTransition(const security::TransitionDescriptor &transition) {
	auto outcome = classifyIbpbTransition(transition, ibpbPolicy().policy(),
		getCpuData()->securityCapabilities);
	if(outcome != IbpbTransitionOutcome::invoked)
		return;

	if constexpr(collectIbpbEvents)
		__atomic_fetch_add(&getCpuData()->securityIbpbAttemptCount, uint64_t{1}, __ATOMIC_RELAXED);

#if defined(THOR_SECURITY_TEST_HOOKS)
	auto completed = predictorBarrierInvokerForTest
			? predictorBarrierInvokerForTest() : issuePredictorBarrier();
	if constexpr(collectIbpbEvents)
		if(completed)
			__atomic_fetch_add(&getCpuData()->securityIbpbCompletedCount, uint64_t{1}, __ATOMIC_RELAXED);
#else
	auto completed = issuePredictorBarrier();
	if constexpr(collectIbpbEvents)
		if(completed)
			__atomic_fetch_add(&getCpuData()->securityIbpbCompletedCount, uint64_t{1}, __ATOMIC_RELAXED);
#endif
}

void reportIbpbDebugSummary() {
	if constexpr(!security::debugMitigations)
		return;
	auto policy = ibpbPolicy().policy();
	uint64_t attempted = 0;
	uint64_t completed = 0;
	for(size_t i = 0; i < getCpuCount(); ++i) {
		auto *cpu = getCpuData(i);
		auto &snapshot = cpu->securityCapabilities;
		attempted += __atomic_load_n(&cpu->securityIbpbAttemptCount, __ATOMIC_RELAXED);
		completed += __atomic_load_n(&cpu->securityIbpbCompletedCount, __ATOMIC_RELAXED);

		const char *policyName;
		const char *reason;
		const char *applicabilityName;
		switch(snapshot.ibpbApplicability) {
			case security::Applicability::affected:
				applicabilityName = "affected";
				break;
			case security::Applicability::notAffected:
				applicabilityName = "not affected";
				break;
			case security::Applicability::unknown:
				applicabilityName = "unknown";
				break;
		}
		switch(policy.request) {
			case security::MechanismRequest::automatic:
				policyName = "auto";
				if(snapshot.ibpbApplicability == security::Applicability::affected)
					reason = snapshot.observed && canIssuePredictorBarrier(snapshot)
						? "eligible on distinct user-process switches"
						: "inactive: local CPUID does not enumerate IBPB";
				else if(snapshot.ibpbApplicability == security::Applicability::notAffected)
					reason = "inactive: vendor evidence marks CPU not affected";
				else
					reason = "inactive: no matching vendor affected-CPU evidence";
				break;
			case security::MechanismRequest::disabled:
				policyName = "disable";
				reason = "inactive: disabled by policy";
				break;
			case security::MechanismRequest::forced:
				policyName = "enable";
				reason = snapshot.observed && canIssuePredictorBarrier(snapshot)
					? "eligible on distinct user-process switches"
					: "inactive: local CPUID does not enumerate IBPB";
				break;
		}
		debugLogger() << "thor: IBPB CPU " << cpu->cpuIndex << "; policy " << policyName
				<< "; local mechanism "
				<< (snapshot.observed && canIssuePredictorBarrier(snapshot)
						? "available" : "unavailable")
				<< "; applicability " << applicabilityName
				<< " (" << (snapshot.ibpbApplicabilityEvidence
						? snapshot.ibpbApplicabilityEvidence->id : "none") << ")"
				<< "; " << reason << frg::endlog;
	}
	debugLogger() << "thor: IBPB attempted " << attempted << ", completed " << completed
			<< frg::endlog;
}

#if defined(THOR_SECURITY_TEST_HOOKS)
void transitionHook(TransitionHook hook) {
	auto &counter = getCpuData()->securityTransitionCounters[static_cast<size_t>(hook)];
	__atomic_fetch_add(&counter, uint64_t{1}, __ATOMIC_RELAXED);
}

uint64_t transitionHookCount(TransitionHook hook) {
	auto &counter = getCpuData()->securityTransitionCounters[static_cast<size_t>(hook)];
	return __atomic_load_n(&counter, __ATOMIC_RELAXED);
}
#endif

static initgraph::Task freezeSecurityPolicyTask{&globalInitEngine, "x86.freeze-security-policy",
		initgraph::Entails{getSecurityPolicyFrozenStage()}, [] {
		// thorMain() initializes the command line before the init graph runs.
		auto &state = security::architectureState();
		auto error = security::parsePolicy(getKernelCmdline(), state.policy());
		if(error != security::PolicyParseError::success)
			panicLogger() << "thor: invalid speculation_security command-line policy: "
					<< static_cast<unsigned int>(error) << frg::endlog;
		error = configureIbpbPolicy(getKernelCmdline(), state.policy().mitigation());
		if(error != security::PolicyParseError::success)
			panicLogger() << "thor: invalid speculation_security.ibpb command-line policy: "
					<< static_cast<unsigned int>(error) << frg::endlog;
		if(!state.registerMitigation(security::TrustBoundary::processToProcess,
				&ibpbMitigationDecision))
			panicLogger() << "thor: failed to register IBPB process-boundary mitigation"
					<< frg::endlog;
		state.freezePolicy();
		ibpbPolicy().freeze();
		if(!state.publishDeferredBoundaryRecords())
			panicLogger() << "thor: failed to publish deferred security boundary records"
					<< frg::endlog;
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
		if(canReadArchCapabilities(snapshot)) {
			// CPUID.07H.00H:EDX[29] is the exact authorization predicate.
			snapshot.archCapabilities = common::x86::rdmsr(0x10A);
			snapshot.archCapabilitiesKnown = true;
		}
	} else if(snapshot.vendor == CpuVendor::amd) {
		snapshot.capabilityEvidence = &amdCpuid;
	}
	determineIbpbApplicability(snapshot);

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
	bool mismatch = false;

	for(size_t i = 0; i < getCpuCount(); ++i) {
		auto &snapshot = getCpuData(i)->securityCapabilities;
		if(!snapshot.observed)
			continue;
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
	if(cpuCapabilitySetFinalized()) {
		debugLogger() << "thor: security capability CPU-set reconciliation complete" << frg::endlog;
		if(!security::architectureState().finalizeBoundaryRecords())
			panicLogger() << "thor: failed to publish initial security boundary records"
					<< frg::endlog;
		reportIbpbDebugSummary();
	}
}

bool cpuCapabilitySetFinalized() {
	for(size_t i = 0; i < getCpuCount(); ++i)
		if(!getCpuData(i)->securityCapabilities.observed)
			return false;
	return true;
}

} // namespace thor::x86_security
