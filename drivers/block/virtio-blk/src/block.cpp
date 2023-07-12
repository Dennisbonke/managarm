
#include "block.hpp"

#include <iostream>
#include <stdlib.h>

namespace block {
namespace virtio {

static bool logInitiateRetire = false;

// --------------------------------------------------------
// UserRequest
// --------------------------------------------------------

UserRequest::UserRequest(bool write_, uint64_t sector_, void *buffer_, size_t num_sectors_)
: write {write_}
, sector {sector_}
, buffer {buffer_}
, numSectors {num_sectors_} {}

// --------------------------------------------------------
// Device
// --------------------------------------------------------

Device::Device(std::unique_ptr<virtio_core::Transport> transport, int64_t parent_id)
: blockfs::BlockDevice {512, parent_id}
, _transport {std::move(transport)}
, _requestQueue {nullptr}
, _size {0} {}

void Device::runDevice() {
	_transport->finalizeFeatures();
	_transport->claimQueues(1);
	_requestQueue = _transport->setupQueue(0);

	auto size =
		static_cast<uint64_t>(_transport->space().load(spec::regs::capacity[0]))
		| (static_cast<uint64_t>(_transport->space().load(spec::regs::capacity[1])) << 32);
	std::cout << "virtio: Disk size: " << size << " sectors" << std::endl;
	_size = size;

	_transport->runDevice();

	// perform device specific setup
	virtRequestBuffer = new VirtRequest[_requestQueue->numDescriptors()];
	statusBuffer = new uint8_t[_requestQueue->numDescriptors()];

	// natural alignment makes sure that request headers do not cross page boundaries
	assert((uintptr_t) virtRequestBuffer % sizeof(VirtRequest) == 0);

	// setup an interrupt for the device
	_processRequests();

	blockfs::runDevice(this);
}

async::result<void> Device::readSectors(uint64_t sector, void *buffer, size_t num_sectors) {
	// Natural alignment makes sure a sector does not cross a page boundary.
	assert(!((uintptr_t) buffer % 512));
	//	printf("readSectors(%lu, %lu)\n", sector, num_sectors);

	// Limit to ensure that we don't monopolize the device.
	auto max_sectors = _requestQueue->numDescriptors() / 4;
	assert(max_sectors >= 1);

	for(size_t progress = 0; progress < num_sectors; progress += max_sectors) {
		auto request = new UserRequest(
			false,
			sector + progress,
			(char *) buffer + 512 * progress,
			std::min(num_sectors - progress, max_sectors)
		);
		_pendingQueue.push(request);
		_pendingDoorbell.raise();
		co_await request->event.wait();
		delete request;
	}
}

async::result<void> Device::writeSectors(uint64_t sector, const void *buffer, size_t num_sectors) {
	// Natural alignment makes sure a sector does not cross a page boundary.
	assert(!((uintptr_t) buffer % 512));
	//	printf("writeSectors(%lu, %lu)\n", sector, num_sectors);

	// Limit to ensure that we don't monopolize the device.
	auto max_sectors = _requestQueue->numDescriptors() / 4;
	assert(max_sectors >= 1);

	for(size_t progress = 0; progress < num_sectors; progress += max_sectors) {
		auto request = new UserRequest(
			true,
			sector + progress,
			(char *) buffer + 512 * progress,
			std::min(num_sectors - progress, max_sectors)
		);
		_pendingQueue.push(request);
		_pendingDoorbell.raise();
		co_await request->event.wait();
		delete request;
	}
}

async::result<size_t> Device::getSize() {
	co_return _size * 512;
}

async::detached Device::_processRequests() {
	while(true) {
		if(_pendingQueue.empty()) {
			co_await _pendingDoorbell.async_wait();
			continue;
		}

		auto request = _pendingQueue.front();
		_pendingQueue.pop();
		assert(request->numSectors);

		// Setup the descriptor for the request header.
		virtio_core::Chain chain;
		chain.append(co_await _requestQueue->obtainDescriptor());

		VirtRequest *header = &virtRequestBuffer[chain.front().tableIndex()];
		if(request->write) {
			header->type = VIRTIO_BLK_T_OUT;
		} else {
			header->type = VIRTIO_BLK_T_IN;
		}
		header->reserved = 0;
		header->sector = request->sector;

		chain.setupBuffer(
			virtio_core::hostToDevice,
			arch::dma_buffer_view {nullptr, header, sizeof(VirtRequest)}
		);

		// Setup descriptors for the transfered data.
		for(size_t i = 0; i < request->numSectors; i++) {
			chain.append(co_await _requestQueue->obtainDescriptor());
			if(request->write) {
				chain.setupBuffer(
					virtio_core::hostToDevice,
					arch::dma_buffer_view {
						nullptr,
						(char *) request->buffer + 512 * i,
						512}
				);
			} else {
				chain.setupBuffer(
					virtio_core::deviceToHost,
					arch::dma_buffer_view {
						nullptr,
						(char *) request->buffer + 512 * i,
						512}
				);
			}
		}

		if(logInitiateRetire) {
			std::cout << "Submitting " << request->numSectors << " data descriptors"
				  << std::endl;
		}

		// Setup a descriptor for the status byte.
		chain.append(co_await _requestQueue->obtainDescriptor());
		chain.setupBuffer(
			virtio_core::deviceToHost,
			arch::dma_buffer_view {
				nullptr,
				&statusBuffer[chain.front().tableIndex()],
				1}
		);

		// Submit the request to the device
		_requestQueue->postDescriptor(
			chain.front(),
			request,
			[](virtio_core::Request *base_request) {
				auto request = static_cast<UserRequest *>(base_request);
				if(logInitiateRetire) {
					std::cout << "Retiring " << request->numSectors
						  << " data descriptors" << std::endl;
				}
				request->event.raise();
			}
		);
		_requestQueue->notify();
	}
}

}  // namespace virtio
}  // namespace block
