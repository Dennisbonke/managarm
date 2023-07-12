#pragma once

#include <arch/register.hpp>
#include <arch/variable.hpp>

//-------------------------------------------------
// Registers
//-------------------------------------------------

namespace op_regs {
constexpr inline arch::bit_register<uint32_t> usbcmd(0);
constexpr inline arch::bit_register<uint32_t> usbsts(0x04);
constexpr inline arch::scalar_register<uint32_t> pagesize(0x8);
constexpr inline arch::scalar_register<uint32_t> dnctrl(0x14);
constexpr inline arch::scalar_register<uint64_t> crcr(0x18);
constexpr inline arch::scalar_register<uint64_t> dcbaap(0x30);
constexpr inline arch::bit_register<uint32_t> config(0x38);
}  // namespace op_regs

namespace cap_regs {
constexpr inline arch::scalar_register<uint8_t> caplength(0);
constexpr inline arch::scalar_register<uint16_t> hciversion(0x02);
constexpr inline arch::bit_register<uint32_t> hcsparams1(0x04);
constexpr inline arch::bit_register<uint32_t> hcsparams2(0x08);
constexpr inline arch::bit_register<uint32_t> hcsparams3(0x0C);
constexpr inline arch::bit_register<uint32_t> hccparams1(0x10);
constexpr inline arch::scalar_register<uint32_t> dboff(0x14);
constexpr inline arch::scalar_register<uint32_t> rtsoff(0x18);
constexpr inline arch::bit_register<uint32_t> hccparams2(0x1C);
}  // namespace cap_regs

namespace hcsparams1 {
constexpr inline arch::field<uint32_t, uint8_t> maxPorts(24, 8);
constexpr inline arch::field<uint32_t, uint16_t> maxIntrs(8, 10);
constexpr inline arch::field<uint32_t, uint8_t> maxDevSlots(0, 8);
}  // namespace hcsparams1

namespace hcsparams2 {
constexpr inline arch::field<uint32_t, uint8_t> ist(0, 4);
constexpr inline arch::field<uint32_t, uint8_t> erstMax(4, 4);
constexpr inline arch::field<uint32_t, uint8_t> maxScratchpadBufsHi(21, 4);
constexpr inline arch::field<uint32_t, bool> scratchpadRestore(26, 1);
constexpr inline arch::field<uint32_t, uint8_t> maxScratchpadBufsLow(27, 4);
}  // namespace hcsparams2

namespace hccparams1 {
constexpr inline arch::field<uint32_t, uint16_t> extCapPtr(16, 16);
constexpr inline arch::field<uint32_t, bool> contextSize(2, 1);
}  // namespace hccparams1

namespace usbcmd {
constexpr inline arch::field<uint32_t, bool> run(0, 1);
constexpr inline arch::field<uint32_t, bool> hcReset(1, 1);
constexpr inline arch::field<uint32_t, bool> intrEnable(2, 1);
}  // namespace usbcmd

namespace usbsts {
constexpr inline arch::field<uint32_t, bool> hcHalted(0, 1);
constexpr inline arch::field<uint32_t, bool> hostSystemErr(2, 1);
constexpr inline arch::field<uint32_t, bool> eventIntr(3, 1);
constexpr inline arch::field<uint32_t, bool> portChange(4, 1);
constexpr inline arch::field<uint32_t, bool> controllerNotReady(11, 1);
constexpr inline arch::field<uint32_t, bool> hostControllerError(12, 1);
}  // namespace usbsts

namespace config {
constexpr inline arch::field<uint32_t, uint8_t> enabledDeviceSlots(0, 8);
}  // namespace config

namespace interrupter {
constexpr inline arch::bit_register<uint32_t> iman(0x0);
constexpr inline arch::scalar_register<uint32_t> imod(0x4);
constexpr inline arch::scalar_register<uint32_t> erstsz(0x8);
constexpr inline arch::scalar_register<uint32_t> erstbaLow(0x10);
constexpr inline arch::scalar_register<uint32_t> erstbaHi(0x14);
constexpr inline arch::scalar_register<uint32_t> erdpLow(0x18);
constexpr inline arch::scalar_register<uint32_t> erdpHi(0x1C);
}  // namespace interrupter

namespace iman {
constexpr inline arch::field<uint32_t, bool> pending(0, 1);
constexpr inline arch::field<uint32_t, bool> enable(1, 1);
}  // namespace iman

namespace port {
constexpr inline arch::bit_register<uint32_t> portsc(0x0);
constexpr inline arch::bit_register<uint32_t> portpmsc(0x4);
constexpr inline arch::bit_register<uint32_t> portli(0x8);
constexpr inline arch::bit_register<uint32_t> porthlpmc(0xC);
}  // namespace port

namespace portsc {
constexpr inline arch::field<uint32_t, bool> portReset(4, 1);
constexpr inline arch::field<uint32_t, bool> portEnable(1, 1);
constexpr inline arch::field<uint32_t, bool> connectStatus(0, 1);
constexpr inline arch::field<uint32_t, bool> portPower(9, 1);
constexpr inline arch::field<uint32_t, uint8_t> portLinkStatus(5, 4);
constexpr inline arch::field<uint32_t, bool> portLinkStatusStrobe(16, 1);
constexpr inline arch::field<uint32_t, uint8_t> portSpeed(10, 4);

constexpr inline arch::field<uint32_t, bool> connectStatusChange(17, 1);
constexpr inline arch::field<uint32_t, bool> portResetChange(21, 1);
constexpr inline arch::field<uint32_t, bool> portEnableChange(18, 1);
constexpr inline arch::field<uint32_t, bool> warmPortResetChange(19, 1);
constexpr inline arch::field<uint32_t, bool> overCurrentChange(20, 1);
constexpr inline arch::field<uint32_t, bool> portLinkStatusChange(22, 1);
constexpr inline arch::field<uint32_t, bool> portConfigErrorChange(23, 1);
}  // namespace portsc
