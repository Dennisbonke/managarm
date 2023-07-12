#pragma once

#include <arch/register.hpp>
#include <arch/variable.hpp>

namespace spec {

namespace format {
constexpr inline uint32_t bgrx = 2;
constexpr inline uint32_t xrgb = 4;
}  // namespace format

namespace cmd {
constexpr inline uint32_t getDisplayInfo = 0x100;
constexpr inline uint32_t create2d = 0x101;
constexpr inline uint32_t setScanout = 0x103;
constexpr inline uint32_t resourceFlush = 0x104;
constexpr inline uint32_t xferToHost2d = 0x105;
constexpr inline uint32_t attachBacking = 0x106;

}  // namespace cmd

namespace resp {
constexpr inline uint32_t noData = 0x1100;
constexpr inline uint32_t displayInfo = 0x1101;
}  // namespace resp

struct Header {
	uint32_t type;
	uint32_t flags;
	uint64_t fenceId;
	uint32_t contextId;
	uint32_t padding;
};

struct Rect {
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
};

struct DisplayInfo {
	Header header;

	struct {
		Rect rect;
		uint32_t enabled;
		uint32_t flags;
	} modes[16];
};

struct Create2d {
	Header header;
	uint32_t resourceId;
	uint32_t format;
	uint32_t width;
	uint32_t height;
};

struct AttachBacking {
	Header header;
	uint32_t resourceId;
	uint32_t numEntries;
};

struct MemEntry {
	uint64_t address;
	uint32_t length;
	uint32_t padding;
};

struct XferToHost2d {
	Header header;
	Rect rect;
	uint64_t offset;
	uint32_t resourceId;
	uint32_t padding;
};

struct SetScanout {
	Header header;
	Rect rect;
	uint32_t scanoutId;
	uint32_t resourceId;
};

struct ResourceFlush {
	Header header;
	Rect rect;
	uint32_t resourceId;
	uint32_t padding;
};

namespace cfg {
constexpr inline arch::scalar_register<uint32_t> numScanouts(8);
}  // namespace cfg

}  // namespace spec
