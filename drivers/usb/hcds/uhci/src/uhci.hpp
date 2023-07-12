
#include <arch/variable.hpp>

struct TransferDescriptor;
struct QueueHead;

enum class Packet : uint8_t {
	in = 0x69,
	out = 0xE1,
	setup = 0x2D
};

namespace td_status {
constexpr static arch::field<uint32_t, uint16_t> actualLength(0, 11);
constexpr static arch::field<uint32_t, uint8_t> errorBits(17, 6);
constexpr static arch::field<uint32_t, bool> bitstuffError(17, 1);
constexpr static arch::field<uint32_t, bool> timeoutError(18, 1);
constexpr static arch::field<uint32_t, bool> nakError(19, 1);
constexpr static arch::field<uint32_t, bool> babbleError(20, 1);
constexpr static arch::field<uint32_t, bool> bufferError(21, 1);
constexpr static arch::field<uint32_t, bool> stalled(22, 1);
constexpr static arch::field<uint32_t, bool> active(23, 1);
constexpr static arch::field<uint32_t, bool> completionIrq(24, 1);
constexpr static arch::field<uint32_t, bool> isochronous(25, 1);
constexpr static arch::field<uint32_t, bool> lowSpeed(26, 1);
constexpr static arch::field<uint32_t, uint8_t> numRetries(27, 2);
constexpr static arch::field<uint32_t, bool> detectShort(29, 1);
}  // namespace td_status

namespace td_token {
constexpr static arch::field<uint32_t, Packet> pid(0, 8);
constexpr static arch::field<uint32_t, uint8_t> address(8, 7);
constexpr static arch::field<uint32_t, uint8_t> pipe(15, 4);
constexpr static arch::field<uint32_t, bool> toggle(19, 1);
constexpr static arch::field<uint32_t, size_t> length(21, 11);
}  // namespace td_token

struct Pointer {
	static Pointer from(TransferDescriptor *item);
	static Pointer from(QueueHead *item);

	constexpr static uint32_t TerminateBit = 0;
	constexpr static uint32_t QhSelectBit = 1;
	constexpr static uint32_t PointerMask = 0xFFFFFFF0;

	Pointer() : _bits(1 << TerminateBit) {}

	Pointer(uint32_t pointer, bool is_queue) : _bits(pointer | (is_queue << QhSelectBit)) {
		assert(pointer % 16 == 0);
	}

	bool isQueue() { return _bits & (1 << QhSelectBit); }

	bool isTerminate() { return _bits & (1 << TerminateBit); }

	uint32_t actualPointer() { return _bits & PointerMask; }

	uint32_t _bits;
};

struct TransferBufferPointer {
	static TransferBufferPointer from(void *item) {
		uintptr_t physical;
		HEL_CHECK(helPointerPhysical(item, &physical));
		assert((physical & 0xFFFFFFFF) == physical);
		return TransferBufferPointer(physical);
	}

	TransferBufferPointer() { _bits = 0; }

	TransferBufferPointer(uint32_t pointer) : _bits(pointer) {}

private:
	uint32_t _bits;
};

// UHCI specifies TDs to be 32 bytes with the last 16 bytes reserved
// for the driver. We just use a 16 byte structure.
struct alignas(16) TransferDescriptor {
	typedef Pointer LinkPointer;

	void dumpStatus() {
		auto s = status.load();
		if(s & td_status::active) {
			std::cout << " active";
		}
		if(s & td_status::stalled) {
			std::cout << " stalled";
		}
		if(s & td_status::bitstuffError) {
			std::cout << " bitstuff-error";
		}
		if(s & td_status::timeoutError) {
			std::cout << " time-out";
		}
		if(s & td_status::nakError) {
			std::cout << " nak";
		}
		if(s & td_status::babbleError) {
			std::cout << " babble-detected";
		}
		if(s & td_status::bufferError) {
			std::cout << " data-buffer-error";
		}
		if(!(s & td_status::errorBits)) {
			std::cout << " no-error";
		}
	}

	LinkPointer _linkPointer;
	arch::bit_variable<uint32_t> status;
	arch::bit_variable<uint32_t> token;
	TransferBufferPointer _bufferPointer;
};

static_assert(sizeof(TransferDescriptor) == 16, "Bad sizeof(TransferDescriptor)");

struct alignas(16) QueueHead {
	typedef Pointer LinkPointer;
	typedef Pointer ElementPointer;

	LinkPointer _linkPointer;
	ElementPointer _elementPointer;
};

struct FrameListPointer {
	constexpr static uint32_t TerminateBit = 0;
	constexpr static uint32_t QhSelectBit = 1;
	constexpr static uint32_t PointerMask = 0xFFFFFFF0;

	static FrameListPointer from(QueueHead *item) {
		uintptr_t physical;
		HEL_CHECK(helPointerPhysical(item, &physical));
		assert(physical % sizeof(*item) == 0);
		assert((physical & 0xFFFFFFFF) == physical);
		return FrameListPointer {static_cast<uint32_t>(physical), true};
	}

	FrameListPointer() : _bits {1 << TerminateBit} {}

	FrameListPointer(uint32_t pointer, bool is_queue)
	: _bits {pointer | (is_queue << QhSelectBit)} {
		assert(pointer % 16 == 0);
	}

	bool isQueue() { return _bits & (1 << QhSelectBit); }

	bool isTerminate() { return _bits & (1 << TerminateBit); }

	uint32_t actualPointer() { return _bits & PointerMask; }

	uint32_t _bits;
};

struct FrameList {
	arch::scalar_variable<uint32_t> entries[1024];
};

enum {
	kPciLegacySupport = 0xC0
};
