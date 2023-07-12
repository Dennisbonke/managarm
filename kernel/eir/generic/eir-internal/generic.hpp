#pragma once

#include <eir-internal/arch/types.hpp>
#include <eir/interface.hpp>
#include <frg/span.hpp>
#include <frg/string.hpp>
#include <stddef.h>
#include <stdint.h>

namespace eir {

enum class RegionType {
	null,
	unconstructed,
	allocatable
};

struct Region {
	RegionType regionType;
	address_t address;
	address_t size;

	int order;
	uint64_t numRoots;
	address_t buddyTree;
	address_t buddyOverhead;
	address_t buddyMap;
};

constexpr static size_t numRegions = 64;
extern Region regions[numRegions];
extern address_t allocatedMemory;

uintptr_t bootReserve(size_t length, size_t alignment);
uintptr_t allocPage();
void allocLogRingBuffer();

void setupRegionStructs();
void createInitialRegion(address_t base, address_t size);

struct InitialRegion {
	address_t base;
	address_t size;
};

void createInitialRegions(InitialRegion region, frg::span<InitialRegion> reserved);

address_t mapBootstrapData(void *p);
void mapKasanShadow(uint64_t address, size_t size);
void unpoisonKasanShadow(uint64_t address, size_t size);
void mapRegionsAndStructs();

address_t loadKernelImage(void *image);

EirInfo *generateInfo(const char *cmdline);

void setFbInfo(void *ptr, int width, int height, size_t pitch);

template<typename T>
T *bootAlloc(size_t n = 1) {
	auto pointer = reinterpret_cast<T *>(bootReserve(sizeof(T) * n, alignof(T)));
	for(size_t i = 0; i < n; i++) {
		new(&pointer[i]) T();
	}
	return pointer;
}

}  // namespace eir
