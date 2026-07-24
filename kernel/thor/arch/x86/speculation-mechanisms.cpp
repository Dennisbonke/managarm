#include <thor-internal/arch/speculation-mechanisms.hpp>

#include <thor-internal/cpu-data.hpp>
#include <x86/machine.hpp>

namespace thor::x86_security {

namespace {

constexpr bool canUpdateSpeculationControl(const CapabilitySnapshot &snapshot,
		SpeculationControlState state) {
	return (!state.ibrs || canWriteIbrs(snapshot))
			&& (!state.stibp || canWriteStibp(snapshot))
			&& (!state.ssbd || canWriteSsbd(snapshot))
			&& canAccessSpeculationControl(snapshot);
}

constexpr CapabilitySnapshot stibpOnlySnapshot{.haveStibp = true};
static_assert(canUpdateSpeculationControl(stibpOnlySnapshot, {.stibp = true}));
static_assert(!canUpdateSpeculationControl(stibpOnlySnapshot, {.ibrs = true}));

} // namespace

void switchAddressSpaceRoot(uintptr_t root) {
	asm volatile ("mov %0, %%cr3" : : "r"(root) : "memory");
}

void speculationFence() {
	asm volatile ("lfence" : : : "memory");
}

bool updateSpeculationControl(SpeculationControlState state) {
	auto &snapshot = getCpuData()->securityCapabilities;
	if(!canUpdateSpeculationControl(snapshot, state))
		return false;

	uint64_t value = (state.ibrs ? uint64_t{1} << 0 : 0)
			| (state.stibp ? uint64_t{1} << 1 : 0)
			| (state.ssbd ? uint64_t{1} << 2 : 0);
	common::x86::wrmsr(0x48, value); // SPEC_CTRL
	return true;
}

bool issuePredictorBarrier() {
	if(!canIssuePredictorBarrier(getCpuData()->securityCapabilities))
		return false;
	common::x86::wrmsr(0x49, 1); // PRED_CMD.IBPB
	return true;
}

bool clearCpuBuffers(uint16_t selector) {
	if(!canClearCpuBuffers(getCpuData()->securityCapabilities))
		return false;

	// The caller owns the descriptor setup; this primitive does not invent a
	// selector or make a vulnerability decision.
	asm volatile ("verw %0" : : "m"(selector) : "cc", "memory");
	return true;
}

void sanitizeReturnPredictions() {
	// The call/return pairs deliberately do not transfer to another context.
	// Keep this fixed-size sequence so later modules can reason about its cost.
	asm volatile (
		".rept 32\n"
		"call 1f\n"
		"1:\n"
		".endr\n"
		"add $256, %%rsp\n"
		: : : "memory");
}

} // namespace thor::x86_security
