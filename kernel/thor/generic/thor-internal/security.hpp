#pragma once

#include <frg/array.hpp>
#include <stddef.h>
#include <stdint.h>

namespace thor::security {

// These are semantic boundaries, not a statement that they are protected.
enum class TrustBoundary : uint8_t {
	userToKernel,
	processToProcess,
	guestToHost,
	guestToGuest,
	smtSibling,
	numBoundaries
};

inline constexpr size_t numTrustBoundaries = static_cast<size_t>(TrustBoundary::numBoundaries);

// A domain is intentionally opaque to the shared layer. Architectures and
// schedulers assign identities; this layer only describes transitions between them.
using SecurityDomain = uint64_t;
inline constexpr SecurityDomain kernelDomain = 0;

enum class Transition : uint8_t {
	lessTrustedToMoreTrusted,
	moreTrustedToLessTrusted,
	domainToDomain,
	hostToGuest,
	guestToHost,
	activeToIdle,
	idleToActive
};

enum class Applicability : uint8_t {
	notAffected,
	affected,
	unknown
};

enum class MechanismAvailability : uint8_t {
	notRequired,
	available,
	unavailable,
	unknown
};

enum class Enforcement : uint8_t {
	notRequired,
	enabled,
	disabledByPolicy,
	failed,
	notAttempted
};

enum class Result : uint8_t {
	notAffected,
	protectedResult,
	unprotected,
	unknown,
	unavailable
};

enum class Reason : uint8_t {
	vendorEstablishedNotAffected,
	enforcementEnabled,
	missingEvidence,
	unknownApplicability,
	mechanismUnavailable,
	mechanismUnknown,
	enforcementDisabledByPolicy,
	enforcementFailed,
	enforcementNotAttempted,
	invalidState,
	requiredBoundaryUnavailable,
	deferredSmtTopologyAndIsolation,
	noRelevantMitigations
};

enum class Vendor : uint8_t {
	unknown,
	intel,
	amd
};

// This points at immutable, compiled-in primary-source provenance. A mitigation
// decision must retain the exact entry used to make it auditable after boot.
struct Evidence {
	const char *id;
	Vendor vendor;
	const char *documentId;
	const char *title;
	const char *revision;
	const char *section;
	const char *vulnerability;
	const char *sourceDigest;
	const char *derivation;
};

enum class MechanismRequest : uint8_t {
	automatic,
	forced,
	disabled
};

enum class BoundaryRequirement : uint8_t {
	permissive,
	required
};

enum class PolicySource : uint8_t {
	defaultValue,
	commandLine
};

struct MitigationPolicy {
	MechanismRequest request{MechanismRequest::automatic};
	PolicySource source{PolicySource::defaultValue};
};

struct BoundaryPolicy {
	BoundaryRequirement requirement{BoundaryRequirement::permissive};
	PolicySource source{PolicySource::defaultValue};
};

// This is intentionally a typed policy representation, rather than a command
// line parser. Option spelling and defaults are a separate policy decision.
class Policy {
public:
	constexpr const MitigationPolicy &mitigation() const {
		return mitigation_;
	}

	constexpr const BoundaryPolicy &boundary(TrustBoundary boundary) const {
		return boundaries_[static_cast<size_t>(boundary)];
	}

	constexpr bool frozen() const {
		return frozen_;
	}

	// Returns false if a frozen policy is changed or a source attempts to set a
	// contradictory value at the same precedence.
	constexpr bool setMitigation(MitigationPolicy policy) {
		if(frozen_)
			return false;
		if(policy.source < mitigation_.source)
			return true;
		if(policy.source == mitigation_.source && policy.request != mitigation_.request)
			return false;
		mitigation_ = policy;
		return true;
	}

	constexpr bool setBoundary(TrustBoundary boundary, BoundaryPolicy policy) {
		if(frozen_)
			return false;
		auto &slot = boundaries_[static_cast<size_t>(boundary)];
		if(policy.source < slot.source)
			return true;
		if(policy.source == slot.source && policy.requirement != slot.requirement)
			return false;
		slot = policy;
		return true;
	}

	constexpr void freeze() {
		frozen_ = true;
	}

private:
	MitigationPolicy mitigation_{};
	frg::array<BoundaryPolicy, numTrustBoundaries> boundaries_{};
	bool frozen_{false};
};

struct DecisionInputs {
	Applicability applicability{Applicability::unknown};
	MechanismAvailability mechanism{MechanismAvailability::unknown};
	Enforcement enforcement{Enforcement::notAttempted};
	MitigationPolicy policy{};
	BoundaryPolicy boundaryPolicy{};
	const Evidence *evidence{nullptr};
};

struct MitigationDecision {
	Applicability applicability;
	MechanismAvailability mechanism;
	Enforcement enforcement;
	MitigationPolicy policy;
	BoundaryPolicy boundaryPolicy;
	Result result;
	Reason reason;
	const Evidence *evidence;
};

// Result is derived only here. In particular, this function refuses to turn
// unknown hardware into protected hardware merely because an action ran.
constexpr MitigationDecision deriveDecision(DecisionInputs input) {
	if(!input.evidence)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				Result::unknown, Reason::missingEvidence, nullptr};

	if(input.applicability == Applicability::notAffected)
		return {input.applicability, MechanismAvailability::notRequired, Enforcement::notRequired,
				input.policy, input.boundaryPolicy, Result::notAffected,
				Reason::vendorEstablishedNotAffected, input.evidence};

	// Policy and enforcement are independent fields, but combinations that
	// contradict the requested policy must never become auditable decisions.
	if((input.policy.request == MechanismRequest::disabled
				&& input.enforcement == Enforcement::enabled)
			|| (input.policy.request != MechanismRequest::disabled
				&& input.enforcement == Enforcement::disabledByPolicy))
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				Result::unknown, Reason::invalidState, input.evidence};

	if(input.applicability == Applicability::unknown)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				Result::unknown, Reason::unknownApplicability, input.evidence};

	// An affected mitigation must have an actual mechanism and either an action
	// outcome or an explicit policy disablement. Do not normalize an impossible
	// combination into protection.
	if(input.mechanism == MechanismAvailability::notRequired
			|| input.enforcement == Enforcement::notRequired)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				Result::unknown, Reason::invalidState, input.evidence};

	auto boundaryRequired = input.boundaryPolicy.requirement == BoundaryRequirement::required;

	if(input.mechanism == MechanismAvailability::unavailable)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				boundaryRequired ? Result::unavailable : Result::unprotected,
				boundaryRequired ? Reason::requiredBoundaryUnavailable
						: Reason::mechanismUnavailable, input.evidence};
	if(input.mechanism == MechanismAvailability::unknown)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				boundaryRequired ? Result::unavailable : Result::unknown,
				boundaryRequired ? Reason::requiredBoundaryUnavailable
						: Reason::mechanismUnknown, input.evidence};

	if(input.enforcement == Enforcement::enabled)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				Result::protectedResult, Reason::enforcementEnabled, input.evidence};
	if(input.enforcement == Enforcement::disabledByPolicy)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				Result::unprotected, Reason::enforcementDisabledByPolicy, input.evidence};
	if(input.enforcement == Enforcement::failed)
		return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
				boundaryRequired ? Result::unavailable : Result::unprotected,
				boundaryRequired ? Reason::requiredBoundaryUnavailable
						: Reason::enforcementFailed, input.evidence};

	return {input.applicability, input.mechanism, input.enforcement, input.policy, input.boundaryPolicy,
			boundaryRequired ? Result::unavailable : Result::unprotected,
			boundaryRequired ? Reason::requiredBoundaryUnavailable
					: Reason::enforcementNotAttempted, input.evidence};
}

struct BoundaryDecision {
	TrustBoundary boundary;
	Result result;
	Reason reason;
	BoundaryPolicy policy;
};

// Keep aggregation defensive even if a future caller constructs a decision
// record directly rather than using deriveDecision().
constexpr bool isAuditableDecision(const MitigationDecision &decision) {
	if(!decision.evidence)
		return decision.result != Result::protectedResult && decision.result != Result::notAffected;
	if((decision.policy.request == MechanismRequest::disabled
				&& decision.enforcement == Enforcement::enabled)
			|| (decision.policy.request != MechanismRequest::disabled
				&& decision.enforcement == Enforcement::disabledByPolicy))
		return false;
	if(decision.result == Result::protectedResult)
		return decision.applicability == Applicability::affected
				&& decision.mechanism == MechanismAvailability::available
				&& decision.enforcement == Enforcement::enabled;
	if(decision.result == Result::notAffected)
		return decision.applicability == Applicability::notAffected
				&& decision.mechanism == MechanismAvailability::notRequired
				&& decision.enforcement == Enforcement::notRequired;
	return true;
}

// A boundary can only be protected when every relevant mitigation is either
// vendor-established not affected or successfully enforced.
constexpr BoundaryDecision aggregateBoundary(TrustBoundary boundary,
		const MitigationDecision *decisions, size_t count, BoundaryPolicy policy) {
	if(boundary == TrustBoundary::smtSibling)
		return {boundary, policy.requirement == BoundaryRequirement::required
					? Result::unavailable : Result::unprotected,
				Reason::deferredSmtTopologyAndIsolation, policy};
	if(!count)
		return {boundary, policy.requirement == BoundaryRequirement::required
					? Result::unavailable : Result::unknown,
				policy.requirement == BoundaryRequirement::required
						? Reason::requiredBoundaryUnavailable : Reason::noRelevantMitigations,
				policy};

	bool unprotected = false;
	bool unknown = false;
	Reason unprotectedReason = Reason::invalidState;
	Reason unknownReason = Reason::invalidState;
	for(size_t i = 0; i < count; ++i) {
		if(!isAuditableDecision(decisions[i]))
			return {boundary, policy.requirement == BoundaryRequirement::required
						? Result::unavailable : Result::unknown,
					policy.requirement == BoundaryRequirement::required
							? Reason::requiredBoundaryUnavailable : Reason::invalidState,
					policy};
		switch(decisions[i].result) {
			case Result::notAffected:
			case Result::protectedResult:
				break;
			case Result::unavailable:
				return {boundary, Result::unavailable, decisions[i].reason, policy};
			case Result::unprotected:
				if(!unprotected)
					unprotectedReason = decisions[i].reason;
				unprotected = true;
				break;
			case Result::unknown:
				if(!unknown)
					unknownReason = decisions[i].reason;
				unknown = true;
				break;
		}
	}
	if(unprotected)
		return {boundary, policy.requirement == BoundaryRequirement::required
					? Result::unavailable : Result::unprotected,
				policy.requirement == BoundaryRequirement::required
						? Reason::requiredBoundaryUnavailable : unprotectedReason,
				policy};
	if(unknown)
		return {boundary, policy.requirement == BoundaryRequirement::required
					? Result::unavailable : Result::unknown,
				policy.requirement == BoundaryRequirement::required
						? Reason::requiredBoundaryUnavailable : unknownReason,
				policy};
	return {boundary, Result::protectedResult, Reason::enforcementEnabled, policy};
}

class ArchitectureState {
public:
	constexpr Policy &policy() {
		return policy_;
	}

	constexpr const Policy &policy() const {
		return policy_;
	}

	constexpr void freezePolicy() {
		policy_.freeze();
	}

private:
	Policy policy_{};
};

ArchitectureState &architectureState();

} // namespace thor::security
