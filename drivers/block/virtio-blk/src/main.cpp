
#include "block.hpp"

#include <assert.h>
#include <async/result.hpp>
#include <hel-syscalls.h>
#include <hel.h>
#include <helix/ipc.hpp>
#include <iostream>
#include <memory>
#include <protocols/hw/client.hpp>
#include <protocols/mbus/client.hpp>
#include <queue>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

// TODO: Support more than one device.

async::detached bindDevice(mbus::Entity entity) {
	protocols::hw::Device hw_device(co_await entity.bind());
	auto transport = co_await virtio_core::discover(
		std::move(hw_device),
		virtio_core::DiscoverMode::transitional
	);

	auto device = new block::virtio::Device {std::move(transport), entity.getId()};
	device->runDevice();

	/*
		auto info = co_await hw_device.getPciInfo();
		assert(info.barInfo[0].ioType == protocols::hw::IoType::kIoTypePort);
		auto bar = co_await hw_device.accessBar(0);
		auto irq = co_await hw_device.accessIrq();

		HEL_CHECK(helEnableIo(bar.getHandle()));

		std::cout << "Setting up the device" << std::endl;
		device.setupDevice(info.barInfo[0].address, std::move(irq));
	*/
}

async::detached observeDevices() {
	auto root = co_await mbus::Instance::global().getRoot();

	auto filter = mbus::Conjunction({
		mbus::EqualsFilter("pci-vendor", "1af4"),
		mbus::EqualsFilter("pci-device", "1001")
		//		mbus::EqualsFilter("pci-device", "1042")
	});

	auto handler =
		mbus::ObserverHandler {}.withAttach([](mbus::Entity entity, mbus::Properties) {
			std::cout << "virtio: Detected block device" << std::endl;
			bindDevice(std::move(entity));
		});

	co_await root.linkObserver(std::move(filter), std::move(handler));
}

// --------------------------------------------------------
// main() function
// --------------------------------------------------------

int main() {
	printf("Starting virtio-block driver\n");

	//	HEL_CHECK(helSetPriority(kHelThisThread, 3));

	observeDevices();
	async::run_forever(helix::currentDispatcher);
}
