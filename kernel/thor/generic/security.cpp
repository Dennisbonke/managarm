#include <thor-internal/security.hpp>

namespace thor::security {

ArchitectureState &architectureState() {
	static ArchitectureState state;
	return state;
}

namespace {
constexpr bool equals(frg::string_view value, const char *literal) {
	size_t length = 0;
	while(literal[length])
		++length;
	if(value.size() != length)
		return false;
	for(size_t i = 0; i < length; ++i)
		if(value[i] != literal[i])
			return false;
	return true;
}

constexpr MechanismRequest parseRequest(frg::string_view value, bool &valid) {
	if(equals(value, "auto"))
		return MechanismRequest::automatic;
	if(equals(value, "on") || equals(value, "enable"))
		return MechanismRequest::forced;
	if(equals(value, "off") || equals(value, "disable"))
		return MechanismRequest::disabled;
	valid = false;
	return MechanismRequest::automatic;
}

constexpr bool hasPrefix(frg::string_view value, const char *prefix) {
	size_t length = 0;
	while(prefix[length])
		++length;
	if(value.size() < length)
		return false;
	for(size_t i = 0; i < length; ++i)
		if(value[i] != prefix[i])
			return false;
	return true;
}

constexpr size_t findEquals(frg::string_view value) {
	for(size_t i = 0; i < value.size(); ++i)
		if(value[i] == '=')
			return i;
	return size_t(-1);
}

constexpr frg::string_view slice(frg::string_view value, size_t offset, size_t length) {
	return frg::string_view{value.data() + offset, length};
}

constexpr bool viewsEqual(frg::string_view a, frg::string_view b) {
	if(a.size() != b.size())
		return false;
	for(size_t i = 0; i < a.size(); ++i)
		if(a[i] != b[i])
			return false;
	return true;
}

constexpr PolicyParseError parseOption(frg::string_view option, Policy &policy) {
	auto equal = findEquals(option);
	if(equal == size_t(-1))
		return PolicyParseError::malformedOption;
	auto name = slice(option, 0, equal);
	auto value = slice(option, equal + 1, option.size() - equal - 1);
	bool valid = true;
	auto request = parseRequest(value, valid);
	if(!valid)
		return PolicyParseError::invalidValue;
	auto setting = MitigationPolicy{request, PolicySource::commandLine};
	if(equals(name, "speculation_security"))
		return policy.setMitigation(setting)
				? PolicyParseError::success : PolicyParseError::conflictingOption;
	return PolicyParseError::malformedOption;
}

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

constexpr MitigationDecision forgedProtected{
		Applicability::affected, MechanismAvailability::available, Enforcement::enabled,
		{}, {}, Result::protectedResult, Reason::enforcementEnabled, nullptr
};
constexpr auto forgedBoundary = aggregateBoundary(TrustBoundary::guestToHost,
		&forgedProtected, 1, {});
static_assert(forgedBoundary.result != Result::protectedResult);

constexpr MitigationDecision forgedDisabledButProtected{
		Applicability::affected, MechanismAvailability::available, Enforcement::enabled,
		{MechanismRequest::disabled, PolicySource::commandLine}, {},
		Result::protectedResult, Reason::enforcementEnabled, &testEvidence
};
constexpr auto forgedDisabledBoundary = aggregateBoundary(TrustBoundary::guestToHost,
		&forgedDisabledButProtected, 1, {});
static_assert(forgedDisabledBoundary.result != Result::protectedResult);

constexpr auto deferredSmtBoundary = aggregateBoundary(TrustBoundary::smtSibling,
		nullptr, 0, {BoundaryRequirement::required, PolicySource::commandLine});
static_assert(deferredSmtBoundary.result == Result::unavailable);
static_assert(!canActivateBoundary(deferredSmtBoundary));

constexpr bool testBoundaryRecordPublication() {
	ArchitectureState state;
	if(!state.policy().setBoundary(TrustBoundary::smtSibling,
			{BoundaryRequirement::required, PolicySource::commandLine}))
		return false;
	state.freezePolicy();
	if(!state.publishDeferredBoundaryRecords())
		return false;
	if(!state.publishUnmitigatedBoundaryRecords())
		return false;
	auto decision = state.boundaryDecision(TrustBoundary::smtSibling);
	if(!decision || decision->result != Result::unavailable
			|| canActivateBoundary(*decision))
		return false;
	for(size_t i = 0; i < numTrustBoundaries; ++i) {
		auto boundary = static_cast<TrustBoundary>(i);
		auto published = state.boundaryDecision(boundary);
		if(!published)
			return false;
		if(boundary != TrustBoundary::smtSibling
				&& (published->result != Result::unknown
					|| published->reason != Reason::noRelevantMitigations
					|| !canActivateBoundary(*published)))
			return false;
	}
	return !state.publishDeferredBoundaryRecords()
			&& !state.publishUnmitigatedBoundaryRecords();
}
static_assert(testBoundaryRecordPublication());
static_assert(!isDomainChange(kernelDomain, kernelDomain));
static_assert(isDomainChange(kernelDomain, SecurityDomain{1}));

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

constexpr PolicyParseError parsePolicyImpl(frg::string_view commandLine, Policy &policy) {
	size_t offset = 0;
	while(offset < commandLine.size()) {
		while(offset < commandLine.size() && (commandLine[offset] == ' ' || commandLine[offset] == '\t'))
			++offset;
		auto begin = offset;
		while(offset < commandLine.size() && commandLine[offset] != ' ' && commandLine[offset] != '\t')
			++offset;
		if(begin == offset)
			continue;
		auto option = slice(commandLine, begin, offset - begin);
		if(equals(option, "speculation_security") || hasPrefix(option, "speculation_security=")) {
			auto error = parseOption(option, policy);
			if(error != PolicyParseError::success)
				return error;
		}
	}
	return PolicyParseError::success;
}

namespace {
constexpr char testCommandLine[] = "unrelated=1 speculation_security=off";
constexpr char conflictingCommandLine[] = "speculation_security=off speculation_security=on";

constexpr PolicyParseError parseTestCommandLine(Policy &policy) {
	return parsePolicyImpl({testCommandLine, sizeof(testCommandLine) - 1}, policy);
}

constexpr bool testPolicyParserAccepts() {
	Policy policy;
	return parseTestCommandLine(policy) == PolicyParseError::success;
}
static_assert(testPolicyParserAccepts());

constexpr bool testPolicyParserSettings() {
	Policy policy;
	if(parseTestCommandLine(policy) != PolicyParseError::success)
		return false;
	return policy.mitigation().request == MechanismRequest::disabled
			&& policy.boundary(TrustBoundary::guestToHost).requirement
					== BoundaryRequirement::permissive;
}
static_assert(testPolicyParserSettings());

constexpr bool testPolicyParserConflict() {
	Policy policy;
	if(parseTestCommandLine(policy) != PolicyParseError::success)
		return false;
	return parsePolicyImpl({conflictingCommandLine, sizeof(conflictingCommandLine) - 1}, policy)
			== PolicyParseError::conflictingOption;
}
static_assert(testPolicyParserConflict());
} // namespace

PolicyParseError parsePolicy(frg::string_view commandLine, Policy &policy) {
	return parsePolicyImpl(commandLine, policy);
}

namespace {
constexpr PolicyParseError parseMitigationPolicyImpl(frg::string_view commandLine,
		frg::string_view mitigation, MitigationPolicy &policy) {
	if(!mitigation.size())
		return PolicyParseError::malformedOption;
	constexpr char prefix[] = "speculation_security.";
	constexpr size_t prefixLength = sizeof(prefix) - 1;
	bool explicitlySet = false;
	size_t offset = 0;
	while(offset < commandLine.size()) {
		while(offset < commandLine.size() && (commandLine[offset] == ' ' || commandLine[offset] == '\t'))
			++offset;
		auto begin = offset;
		while(offset < commandLine.size() && commandLine[offset] != ' ' && commandLine[offset] != '\t')
			++offset;
		if(begin == offset)
			continue;
		auto option = slice(commandLine, begin, offset - begin);
		if(!hasPrefix(option, prefix))
			continue;
		auto equal = findEquals(option);
		if(equal == size_t(-1)) {
			auto name = slice(option, prefixLength, option.size() - prefixLength);
			if(viewsEqual(name, mitigation))
				return PolicyParseError::malformedOption;
			continue;
		}
		auto name = slice(option, prefixLength, equal - prefixLength);
		// Mitigation names are string views, so compare their exact bounded
		// spelling rather than treating them as NUL-terminated strings.
		if(!viewsEqual(name, mitigation))
			continue;
		bool valid = true;
		auto request = parseRequest(slice(option, equal + 1, option.size() - equal - 1), valid);
		if(!valid)
			return PolicyParseError::invalidValue;
		if(explicitlySet && request != policy.request)
			return PolicyParseError::conflictingOption;
		policy = {request, PolicySource::commandLine};
		explicitlySet = true;
	}
	return PolicyParseError::success;
}

constexpr bool testFutureMitigationParser() {
	// "testing_only" is intentionally not a kernel mitigation. This exercises
	// the registration-facing parser without inventing a production selector.
	constexpr char commandLine[] = "speculation_security=off "
			"speculation_security.testing_only=enable";
	MitigationPolicy policy{MechanismRequest::disabled, PolicySource::commandLine};
	if(parseMitigationPolicyImpl({commandLine, sizeof(commandLine) - 1},
				{"testing_only", sizeof("testing_only") - 1}, policy)
				!= PolicyParseError::success)
		return false;
	return policy.request == MechanismRequest::forced;
}
static_assert(testFutureMitigationParser());

constexpr bool testMalformedMitigationOption() {
	constexpr char commandLine[] = "speculation_security.testing_only";
	MitigationPolicy policy{};
	return parseMitigationPolicyImpl({commandLine, sizeof(commandLine) - 1},
			{"testing_only", sizeof("testing_only") - 1}, policy)
			== PolicyParseError::malformedOption;
}
static_assert(testMalformedMitigationOption());
} // namespace

PolicyParseError parseMitigationPolicy(frg::string_view commandLine,
		frg::string_view mitigation, MitigationPolicy &policy) {
	return parseMitigationPolicyImpl(commandLine, mitigation, policy);
}

} // namespace thor::security
