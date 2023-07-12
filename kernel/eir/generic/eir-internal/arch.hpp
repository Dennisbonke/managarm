#pragma once

#include <eir-internal/arch/types.hpp>
#include <stddef.h>
#include <stdint.h>

namespace eir {

void debugPrintChar(char c);

// read and privileged/supervisor is implied
namespace PageFlags {
constexpr inline static uint32_t write = 1;
constexpr inline static uint32_t execute = 2;
constexpr inline static uint32_t global = 4;
}  // namespace PageFlags

enum class CachingMode {
	null,
	writeCombine,
	mmio
};  // enum class CachingMode

constexpr static int pageShift = 12;
constexpr static size_t pageSize = size_t(1) << pageShift;

void setupPaging();
void mapSingle4kPage(
	address_t address,
	address_t physical,
	uint32_t flags,
	CachingMode caching_mode = CachingMode::null
);
address_t getSingle4kPage(address_t address);

void initProcessorEarly();
void initProcessorPaging(void *kernel_start, uint64_t &kernel_entry);

extern "C" char eirImageFloor;
extern "C" char eirImageCeiling;

}  // namespace eir
