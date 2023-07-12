
#include <arch/register.hpp>

// ----------------------------------------------------------------------------
// GMBUS registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> gmbusSelect(0x5100);
constexpr static arch::bit_register<uint32_t> gmbusCommand(0x5104);
constexpr static arch::bit_register<uint32_t> gmbusStatus(0x5108);
constexpr static arch::scalar_register<uint32_t> gmbusData(0x510C);
}  // namespace regs

enum class PinPair {
	analog = 2
};

namespace gmbus_select {
constexpr static arch::field<uint32_t, PinPair> pairSelect(0, 3);
}  // namespace gmbus_select

enum class BusCycle {
	null = 0,
	wait = 1,
	stop = 4
};

namespace gmbus_command {
constexpr static arch::field<uint32_t, bool> issueRead(0, 1);
constexpr static arch::field<uint32_t, unsigned int> address(1, 7);
constexpr static arch::field<uint32_t, size_t> byteCount(16, 9);
constexpr static arch::field<uint32_t, BusCycle> cycleSelect(25, 3);
constexpr static arch::field<uint32_t, bool> enableTimeout(29, 1);
constexpr static arch::field<uint32_t, bool> softwareReady(30, 1);
constexpr static arch::field<uint32_t, bool> clearError(31, 1);
}  // namespace gmbus_command

namespace gmbus_status {
constexpr static arch::field<uint32_t, bool> nakIndicator(10, 1);
constexpr static arch::field<uint32_t, bool> hardwareReady(11, 1);
constexpr static arch::field<uint32_t, bool> slaveStall(13, 1);
constexpr static arch::field<uint32_t, bool> waitPhase(14, 1);
}  // namespace gmbus_status

// ----------------------------------------------------------------------------
// Clock (aka DPLL) registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> vgaPllDivisor1(0x6000);
constexpr static arch::bit_register<uint32_t> vgaPllDivisor2(0x6004);
constexpr static arch::bit_register<uint32_t> vgaPllPost(0x6010);
constexpr static arch::bit_register<uint32_t> pllControl(0x6014);
constexpr static arch::bit_register<uint32_t> busMultiplier(0x601C);
constexpr static arch::bit_register<uint32_t> pllDivisor1(0x6040);
constexpr static arch::bit_register<uint32_t> pllDivisor2(0x6044);
}  // namespace regs

namespace pll_control {
constexpr static arch::field<uint32_t, unsigned int> phase(9, 4);
constexpr static arch::field<uint32_t, unsigned int> encodedP1(16, 8);
constexpr static arch::field<uint32_t, unsigned int> modeSelect(26, 2);
constexpr static arch::field<uint32_t, bool> disableVga(28, 1);
constexpr static arch::field<uint32_t, bool> enablePll(31, 1);
}  // namespace pll_control

namespace bus_multiplier {
constexpr static arch::field<uint32_t, unsigned int> vgaMultiplier(0, 6);
constexpr static arch::field<uint32_t, unsigned int> dacMultiplier(8, 6);
}  // namespace bus_multiplier

namespace pll_divisor {
constexpr static arch::field<uint32_t, unsigned int> m2(0, 6);
constexpr static arch::field<uint32_t, unsigned int> m1(8, 6);
constexpr static arch::field<uint32_t, unsigned int> n(16, 6);
}  // namespace pll_divisor

// ----------------------------------------------------------------------------
// Pipe timing registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> htotal(0x60000);
constexpr static arch::bit_register<uint32_t> hblank(0x60004);
constexpr static arch::bit_register<uint32_t> hsync(0x60008);
constexpr static arch::bit_register<uint32_t> vtotal(0x6000C);
constexpr static arch::bit_register<uint32_t> vblank(0x60010);
constexpr static arch::bit_register<uint32_t> vsync(0x60014);
constexpr static arch::bit_register<uint32_t> sourceSize(0x6001C);
}  // namespace regs

namespace hvtotal {
constexpr static arch::field<uint32_t, unsigned int> active(0, 12);
constexpr static arch::field<uint32_t, unsigned int> total(16, 13);
}  // namespace hvtotal

namespace hvblank {
constexpr static arch::field<uint32_t, unsigned int> start(0, 13);
constexpr static arch::field<uint32_t, unsigned int> end(16, 13);
}  // namespace hvblank

namespace hvsync {
constexpr static arch::field<uint32_t, unsigned int> start(0, 13);
constexpr static arch::field<uint32_t, unsigned int> end(16, 13);
}  // namespace hvsync

namespace source_size {
constexpr static arch::field<uint32_t, unsigned int> horizontal(16, 12);
constexpr static arch::field<uint32_t, unsigned int> vertical(0, 12);
}  // namespace source_size

// ----------------------------------------------------------------------------
// Port registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> dacPort(0x61100);
}  // namespace regs

namespace dac_port {
constexpr static arch::field<uint32_t, bool> enableDac(31, 1);
}  // namespace dac_port

// ----------------------------------------------------------------------------
// Pipe registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> pipeConfig(0x70008);
}  // namespace regs

namespace pipe_config {
constexpr static arch::field<uint32_t, bool> pipeStatus(30, 1);
constexpr static arch::field<uint32_t, bool> enablePipe(31, 1);
}  // namespace pipe_config

// ----------------------------------------------------------------------------
// Primary plane registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> planeControl(0x70180);
constexpr static arch::scalar_register<uint32_t> planeOffset(0x70184);
constexpr static arch::scalar_register<uint32_t> planeStride(0x70188);
constexpr static arch::scalar_register<uint32_t> planeAddress(0x7019C);
}  // namespace regs

enum class PrimaryFormat : unsigned int {
	INDEXED = 2,
	BGRX8888 = 6,
	RGBX8888 = 14
};

namespace plane_control {
constexpr static arch::field<uint32_t, bool> enablePlane(31, 1);
constexpr static arch::field<uint32_t, PrimaryFormat> pixelFormat(26, 4);
}  // namespace plane_control

namespace vga_control {
constexpr static arch::field<uint32_t, bool> disableVga(31, 1);
constexpr static arch::field<uint32_t, unsigned int> centeringMode(30, 2);
}  // namespace vga_control

// ----------------------------------------------------------------------------
// VGA BIOS registers.
// ----------------------------------------------------------------------------

namespace regs {
constexpr static arch::bit_register<uint32_t> vgaControl(0x71400);
}  // namespace regs
