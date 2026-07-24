#include <thor-internal/security.hpp>

namespace thor::security {

ArchitectureState &architectureState() {
	static ArchitectureState state;
	return state;
}

namespace {
constexpr Evidence testEvidence{
		"test.evidence", Vendor::intel, "test", "test", "test", "test", "test", "", "test"
};

constexpr auto notAffected = deriveDecision({
		Applicability::notAffected, MechanismAvailability::notRequired,
		Enforcement::notRequired, {}, {}, &testEvidence
});
static_assert(notAffected.result == Result::notAffected);

constexpr auto unknownWithAction = deriveDecision({
		Applicability::unknown, MechanismAvailability::available,
		Enforcement::enabled, {}, {}, &testEvidence
});
static_assert(unknownWithAction.result == Result::unknown);

constexpr auto affectedAndEnabled = deriveDecision({
		Applicability::affected, MechanismAvailability::available,
		Enforcement::enabled, {}, {}, &testEvidence
});
static_assert(affectedAndEnabled.result == Result::protectedResult);

constexpr auto missingEvidence = deriveDecision({
		Applicability::affected, MechanismAvailability::available,
		Enforcement::enabled, {}, {}, nullptr
});
static_assert(missingEvidence.result != Result::protectedResult);

constexpr auto impossibleState = deriveDecision({
		Applicability::affected, MechanismAvailability::notRequired,
		Enforcement::enabled, {}, {}, &testEvidence
});
static_assert(impossibleState.result != Result::protectedResult);

constexpr auto disabledButEnabled = deriveDecision({
		Applicability::affected, MechanismAvailability::available,
		Enforcement::enabled, {MechanismRequest::disabled, PolicySource::commandLine},
		{}, &testEvidence
});
static_assert(disabledButEnabled.result == Result::unknown);
static_assert(disabledButEnabled.reason == Reason::invalidState);

constexpr auto automaticButDisabled = deriveDecision({
		Applicability::affected, MechanismAvailability::available,
		Enforcement::disabledByPolicy, {}, {}, &testEvidence
});
static_assert(automaticButDisabled.result == Result::unknown);
static_assert(automaticButDisabled.reason == Reason::invalidState);

constexpr auto unavailableMechanism = deriveDecision({
		Applicability::affected, MechanismAvailability::unavailable,
		Enforcement::notAttempted, {}, {}, &testEvidence
});
constexpr auto unavailableBoundary = aggregateBoundary(TrustBoundary::userToKernel,
		&unavailableMechanism, 1, {});
static_assert(unavailableBoundary.result == Result::unprotected);
static_assert(unavailableBoundary.reason == Reason::mechanismUnavailable);

constexpr bool testPolicyFreeze() {
	Policy policy;
	if(!policy.setBoundary(TrustBoundary::guestToHost,
				{BoundaryRequirement::required, PolicySource::commandLine}))
		return false;
	if(policy.setBoundary(TrustBoundary::guestToHost,
				{BoundaryRequirement::permissive, PolicySource::commandLine}))
		return false;
	policy.freeze();
	return !policy.setMitigation({MechanismRequest::disabled, PolicySource::commandLine});
}
static_assert(testPolicyFreeze());
} // namespace

} // namespace thor::security
