#pragma once

#include <stdint.h>

namespace thor::x86_security {

// These interfaces perform no policy or applicability decision. A mitigation
// module must first select them through an evidence-backed decision and call
// them only at the transition phase justified by that module's design record.

// Writes CR3 exactly once. The caller owns PCID/no-flush encoding and must have
// established that the root is valid in the current paging mode.
void switchAddressSpaceRoot(uintptr_t root);

// Orders locally preceding memory operations before following operations. Later
// mitigation modules must document why LFENCE supplies the needed ordering on
// their supported vendor/processor set.
void speculationFence();

struct SpeculationControlState {
	bool ibrs{false};
	bool stibp{false};
	bool ssbd{false};
};

// Updates only the architecturally defined SPEC_CTRL fields. Every requested
// field is checked against its own Intel or AMD CPUID predicate; reserved or
// unenumerated bits cannot be expressed through this interface.
bool updateSpeculationControl(SpeculationControlState state);

// Issues PRED_CMD.IBPB only if the vendor-specific CPUID predicate authorizes
// it. Returns false without writing an MSR when unavailable.
bool issuePredictorBarrier();

// Executes VERW-based buffer clearing only if CPUID.07H.00H:EDX[10] enumerates
// MD_CLEAR. The selector must name a caller-provisioned writable data segment.
// Returns false without executing VERW when unavailable.
bool clearCpuBuffers(uint16_t selector);

// Fills the return stack buffer with controlled returns. This has no policy of
// its own and is not invoked by the foundation transition hooks.
void sanitizeReturnPredictions();

} // namespace thor::x86_security
