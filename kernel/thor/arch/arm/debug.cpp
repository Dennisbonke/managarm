#include <arch/aarch64/mem_space.hpp>
#include <arch/register.hpp>
#include <thor-internal/arch/debug.hpp>

namespace thor {

constinit UartLogHandler uartLogHandler;

void setupDebugging() {
	enableLogHandler(&uartLogHandler);
}

namespace {
namespace reg {
constexpr static arch::scalar_register<uint32_t> data {0x00};
constexpr static arch::bit_register<uint32_t> status {0x18};
}  // namespace reg

namespace status {
constexpr static arch::field<uint32_t, bool> tx_full {5, 1};
};  // namespace status

constexpr static arch::mem_space space {0xFFFF000000000000};

}  // namespace

void UartLogHandler::printChar(char c) {
	// Here we depend on a few things:
	// 1. Eir has mapped the UART to 0xFFFF000000000000
	// 2. The UART is at least somewhat PL011 compatible
	// 3. The UART is already configured by Eir to some sensible settings

	while(space.load(reg::status) & status::tx_full)
		;

	space.store(reg::data, c);
}

}  // namespace thor
