
#include <queue>

#include <arch/mem_space.hpp>
#include <arch/dma_structs.hpp>
#include <async/recurring-event.hpp>
#include <async/promise.hpp>
#include <async/mutex.hpp>
#include <async/result.hpp>
#include <boost/intrusive/list.hpp>
#include <helix/memory.hpp>
#include <frg/expected.hpp>
#include <frg/std_compat.hpp>
#include <protocols/hw/client.hpp>
#include <protocols/mbus/client.hpp>
#include <protocols/usb/api.hpp>

#include "spec.hpp"

namespace proto = protocols::usb;

struct Controller;
struct DeviceState;
struct ConfigurationState;
struct InterfaceState;
struct EndpointState;

// TODO: This could be moved to a "USB core" driver.
struct Enumerator {
	Enumerator(Controller *controller);

	// Called by the USB hub driver once a device connects to a port.
	void connectPort(int port);

	// Called by the USB hub driver once a device completes reset.
	void enablePort(int port);

	// Called by the USB hub driver if a port fails to enable after connection
	void disablePort(int port);

private:
	async::detached _reset(int port);
	async::detached _probe();

	Controller *_controller;
	int _activePort;
	async::mutex _addressMutex;
};

// ----------------------------------------------------------------
// Controller.
// ----------------------------------------------------------------

struct Controller : std::enable_shared_from_this<Controller> {
	Controller(protocols::hw::Device hw_device,
			mbus_ng::EntityManager entity,
			helix::Mapping mapping,
			helix::UniqueDescriptor mmio, helix::UniqueIrq irq);

	async::detached initialize();
	async::result<void> probeDevice();
	async::detached handleIrqs();

	// ------------------------------------------------------------------------
	// Schedule classes.
	// ------------------------------------------------------------------------

	struct AsyncItem : boost::intrusive::list_base_hook<> {

	};

	struct Transaction : AsyncItem {
		explicit Transaction(arch::dma_array<TransferDescriptor> transfers, size_t size)
		: transfers{std::move(transfers)}, fullSize{size},
				numComplete{0}, lostSize{0} { }

		arch::dma_array<TransferDescriptor> transfers;
		size_t fullSize;
		size_t numComplete;
		size_t lostSize; // Size lost in short packets.
		async::promise<frg::expected<proto::UsbError, size_t>, frg::stl_allocator> promise;
		async::promise<frg::expected<proto::UsbError>, frg::stl_allocator> voidPromise;
	};

	struct QueueEntity : AsyncItem {
		QueueEntity(arch::dma_object<QueueHead> the_head, int address,
				int pipe, proto::PipeType type, size_t packet_size);

		bool getReclaim();
		void setReclaim(bool reclaim);
		void setAddress(int address);
		arch::dma_object<QueueHead> head;
		boost::intrusive::list<Transaction> transactions;
	};


	// ------------------------------------------------------------------------
	// Device management.
	// ------------------------------------------------------------------------

	struct EndpointSlot {
		size_t maxPacketSize;
		QueueEntity *queueEntity;
	};

	struct DeviceSlot {
		EndpointSlot controlStates[16];
		EndpointSlot outStates[16];
		EndpointSlot inStates[16];
	};

	std::queue<int> _addressStack;
	DeviceSlot _activeDevices[128];

public:
	async::result<frg::expected<proto::UsbError, std::string>> deviceDescriptor(int address);
	async::result<frg::expected<proto::UsbError, std::string>> configurationDescriptor(int address, uint8_t configuration);

	async::result<frg::expected<proto::UsbError>>
	useConfiguration(int address, int configuration);

	async::result<frg::expected<proto::UsbError>>
	useInterface(int address, int interface, int alternative);

	// ------------------------------------------------------------------------
	// Transfer functions.
	// ------------------------------------------------------------------------

	static Transaction *_buildControl(proto::XferFlags dir,
			arch::dma_object_view<proto::SetupPacket> setup, arch::dma_buffer_view buffer,
			size_t max_packet_size);
	static Transaction *_buildInterruptOrBulk(proto::XferFlags dir,
			arch::dma_buffer_view buffer, size_t max_packet_size,
			bool lazy_notification);


	async::result<frg::expected<proto::UsbError>>
	transfer(int address, int pipe, proto::ControlTransfer info);

	async::result<frg::expected<proto::UsbError, size_t>>
	transfer(int address, proto::PipeType type, int pipe, proto::InterruptTransfer info);

	async::result<frg::expected<proto::UsbError, size_t>>
	transfer(int address, proto::PipeType type, int pipe, proto::BulkTransfer info);

private:
	async::result<frg::expected<proto::UsbError>> _directTransfer(proto::ControlTransfer info,
			QueueEntity *queue, size_t max_packet_size);


	// ------------------------------------------------------------------------
	// Schedule management.
	// ------------------------------------------------------------------------

	void _linkAsync(QueueEntity *entity);
	void _linkTransaction(QueueEntity *queue, Transaction *transaction);

	void _progressSchedule();
	void _progressQueue(QueueEntity *entity);

	boost::intrusive::list<QueueEntity> _asyncSchedule;
	arch::dma_object<QueueHead> _asyncQh;

	// ----------------------------------------------------------------------------
	// Port management.
	// ----------------------------------------------------------------------------

	void _checkPorts();

public:
	async::detached resetPort(int number);

	// ----------------------------------------------------------------------------
	// Debugging functions.
	// ----------------------------------------------------------------------------
private:
	void _dump(Transaction *transaction);
	void _dump(QueueEntity *entity);


private:
	protocols::hw::Device _hwDevice;
	helix::Mapping _mapping;
	helix::UniqueDescriptor _mmio;
	helix::UniqueIrq _irq;
	arch::mem_space _space;
	arch::mem_space _operational;

	int _numPorts;
	Enumerator _enumerator;

	mbus_ng::EntityManager _entity;
};

// ----------------------------------------------------------------------------
// DeviceState
// ----------------------------------------------------------------------------

struct DeviceState final : proto::DeviceData {
	explicit DeviceState(std::shared_ptr<Controller> controller, int device);

	arch::dma_pool *setupPool() override;
	arch::dma_pool *bufferPool() override;

	async::result<frg::expected<proto::UsbError, std::string>> deviceDescriptor() override;
	async::result<frg::expected<proto::UsbError, std::string>> configurationDescriptor(uint8_t configuration) override;
	async::result<frg::expected<proto::UsbError, proto::Configuration>> useConfiguration(int number) override;
	async::result<frg::expected<proto::UsbError>> transfer(proto::ControlTransfer info) override;

private:
	std::shared_ptr<Controller> _controller;
	int _device;
};

// ----------------------------------------------------------------------------
// ConfigurationState
// ----------------------------------------------------------------------------

struct ConfigurationState final : proto::ConfigurationData {
	explicit ConfigurationState(std::shared_ptr<Controller> controller,
			int device, int configuration);

	async::result<frg::expected<proto::UsbError, proto::Interface>>
	useInterface(int number, int alternative) override;

private:
	std::shared_ptr<Controller> _controller;
	int _device;
	int _configuration;
};

// ----------------------------------------------------------------------------
// InterfaceState
// ----------------------------------------------------------------------------

struct InterfaceState final : proto::InterfaceData {
	explicit InterfaceState(std::shared_ptr<Controller> controller,
			int device, int configuration);

	async::result<frg::expected<proto::UsbError, proto::Endpoint>>
	getEndpoint(proto::PipeType type, int number) override;

private:
	std::shared_ptr<Controller> _controller;
	int _device;
	int _interface;
};

// ----------------------------------------------------------------------------
// EndpointState
// ----------------------------------------------------------------------------

struct EndpointState final : proto::EndpointData {
	explicit EndpointState(std::shared_ptr<Controller> controller,
			int device, proto::PipeType type, int endpoint);

	async::result<frg::expected<proto::UsbError>> transfer(proto::ControlTransfer info) override;
	async::result<frg::expected<proto::UsbError, size_t>> transfer(proto::InterruptTransfer info) override;
	async::result<frg::expected<proto::UsbError, size_t>> transfer(proto::BulkTransfer info) override;

private:
	std::shared_ptr<Controller> _controller;
	int _device;
	proto::PipeType _type;
	int _endpoint;
};

