#pragma once

#include "api.hpp"
#include "usb.hpp"

#include <arch/dma_structs.hpp>
#include <async/mutex.hpp>
#include <async/result.hpp>
#include <frg/expected.hpp>
#include <memory>

// ----------------------------------------------------------------
// Hub.
// ----------------------------------------------------------------

namespace HubStatus {
constexpr static uint32_t connect = 0x01;
constexpr static uint32_t enable = 0x02;
constexpr static uint32_t reset = 0x04;
}  // namespace HubStatus

struct PortState {
	uint32_t status;
	uint32_t changes;
};

struct HubCharacteristics {
	int ttThinkTime;  // In FS bit times
};

struct Hub {
protected:
	~Hub() = default;

public:
	Hub(std::shared_ptr<Hub> parent, size_t port) : parent_ {parent}, port_ {port} {}

	virtual size_t numPorts() = 0;
	virtual async::result<PortState> pollState(int port) = 0;
	virtual async::result<frg::expected<UsbError, DeviceSpeed>> issueReset(int port) = 0;

	virtual frg::expected<UsbError, HubCharacteristics> getCharacteristics() {
		return UsbError::unsupported;
	}

	virtual std::optional<Device> associatedDevice() { return std::nullopt; }

	std::shared_ptr<Hub> parent() const { return parent_; }

	size_t port() const { return port_; }

private:
	std::shared_ptr<Hub> parent_;
	size_t port_;
};

async::result<frg::expected<UsbError, std::shared_ptr<Hub>>>
createHubFromDevice(std::shared_ptr<Hub> parentHub, Device device, size_t port);

// ----------------------------------------------------------------
// Enumerator.
// ----------------------------------------------------------------

struct Enumerator {
	Enumerator(BaseController *controller) : controller_ {controller} {}

	void observeHub(std::shared_ptr<Hub> hub);

private:
	async::detached observePort_(std::shared_ptr<Hub> hub, int port);
	async::result<void> observationCycle_(std::shared_ptr<Hub> hub, int port);

	BaseController *controller_;
	async::mutex enumerateMutex_;
};
