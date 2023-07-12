#pragma once

#include <stdint.h>

namespace posix {

constexpr inline uint32_t superGetProcessData = 1;
constexpr inline uint32_t superFork = 2;
constexpr inline uint32_t superExecve = 3;
constexpr inline uint32_t superExit = 4;
constexpr inline uint32_t superSigKill = 5;
constexpr inline uint32_t superSigRestore = 6;
constexpr inline uint32_t superSigMask = 7;
constexpr inline uint32_t superSigRaise = 8;
constexpr inline uint32_t superClone = 9;
constexpr inline uint32_t superAnonAllocate = 10;
constexpr inline uint32_t superAnonDeallocate = 11;
constexpr inline uint32_t superSigAltStack = 12;
constexpr inline uint32_t superSigSuspend = 13;
constexpr inline uint32_t superGetTid = 14;
constexpr inline uint32_t superGetServerData = 64;

}  // namespace posix
