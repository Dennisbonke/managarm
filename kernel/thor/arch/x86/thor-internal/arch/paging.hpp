#pragma once

#include <atomic>

#include <frg/list.hpp>
#include <assert.h>
#include <smarter.hpp>
#include <thor-internal/mm-rc.hpp>
#include <thor-internal/types.hpp>
#include <thor-internal/work-queue.hpp>

namespace thor {

enum {
	kPageSize = 0x1000,
	kPageShift = 12
};

constexpr Word kPfAccess = 1;
constexpr Word kPfWrite = 2;
constexpr Word kPfUser = 4;
constexpr Word kPfBadTable = 8;
constexpr Word kPfInstruction = 16;

inline void *mapDirectPhysical(PhysicalAddr physical) {
	assert(physical < 0x4000'0000'0000);
	return reinterpret_cast<void *>(0xFFFF'8000'0000'0000 + physical);
}

inline PhysicalAddr reverseDirectPhysical(void *pointer) {
	return reinterpret_cast<uintptr_t>(pointer) - 0xFFFF'8000'0000'0000;
}

struct PageAccessor {
	friend void swap(PageAccessor &a, PageAccessor &b) {
		using std::swap;
		swap(a._pointer, b._pointer);
	}

	PageAccessor()
	: _pointer{nullptr} { }

	PageAccessor(PhysicalAddr physical) {
		assert(physical != PhysicalAddr(-1) && "trying to access invalid physical page");
		assert(!(physical & (kPageSize - 1)) && "physical page is not aligned");
		assert(physical < 0x4000'0000'0000);
		_pointer = reinterpret_cast<void *>(0xFFFF'8000'0000'0000 + physical);
	}

	PageAccessor(const PageAccessor &) = delete;

	PageAccessor(PageAccessor &&other)
	: PageAccessor{} {
		swap(*this, other);
	}

	~PageAccessor() { }

	PageAccessor &operator= (PageAccessor other) {
		swap(*this, other);
		return *this;
	}

	explicit operator bool () {
		return _pointer;
	}

	void *get() {
		return _pointer;
	}

private:
	void *_pointer;
};

struct RetireNode {
	friend struct PageSpace;
	friend struct PageBinding;

	virtual void complete() = 0;

protected:
	~RetireNode() = default;
};

struct ShootNode {
	friend struct PageSpace;
	friend struct PageBinding;
	friend struct KernelPageSpace;
	friend struct GlobalPageBinding;

	VirtualAddr address;
	size_t size;

	virtual void complete() = 0;

protected:
	~ShootNode() = default;

private:
	// This CPU already performed synchronous shootdown,
	// hence it can ignore this request during asynchronous shootdown.
	void *_initiatorCpu;

	uint64_t _sequence;

	std::atomic<unsigned int> _bindingsToShoot;

	frg::default_list_hook<ShootNode> _queueNode;
};

// Functions for debugging kernel page access:
// Deny all access to the physical mapping.
void poisonPhysicalAccess(PhysicalAddr physical);
// Deny write access to the physical mapping.
void poisonPhysicalWriteAccess(PhysicalAddr physical);

struct PageSpace;
struct PageBinding;

static constexpr int maxPcidCount = 8;

// Per-CPU context for paging.
struct PageContext {
	friend struct PageBinding;

	PageContext();

	PageContext(const PageContext &) = delete;

	PageContext &operator= (const PageContext &) = delete;

private:
	// Timestamp for the LRU mechansim of PCIDs.
	uint64_t _nextStamp;

	// Current primary binding (i.e. the currently active PCID).
	PageBinding *_primaryBinding;
};

struct PageBinding {
	PageBinding();

	PageBinding(const PageBinding &) = delete;

	PageBinding &operator= (const PageBinding &) = delete;

	smarter::shared_ptr<PageSpace> boundSpace() {
		return _boundSpace;
	}

	void setupPcid(int pcid) {
		assert(!_pcid);
		_pcid = pcid;
	}

	int getPcid() {
		return _pcid;
	}

	uint64_t primaryStamp() {
		return _primaryStamp;
	}

	bool isPrimary();

	void rebind();

	void rebind(smarter::shared_ptr<PageSpace> space);

	void unbind();

	void shootdown();

private:
	int _pcid;

	// TODO: Once we can use libsmarter in the kernel, we should make this a shared_ptr
	//       to the PageSpace that does *not* prevent the PageSpace from becoming
	//       "activatable".
	smarter::shared_ptr<PageSpace> _boundSpace;

	uint64_t _primaryStamp;

	uint64_t _alreadyShotSequence;
};

struct GlobalPageBinding {
	GlobalPageBinding();

	GlobalPageBinding(const GlobalPageBinding &) = delete;

	GlobalPageBinding &operator= (const GlobalPageBinding &) = delete;

	void bind();

	void shootdown();

private:
	uint64_t _alreadyShotSequence;
};

struct PageSpace {
	static void activate(smarter::shared_ptr<PageSpace> space);

	friend struct PageBinding;

	PageSpace(PhysicalAddr root_table);

	~PageSpace();

	PhysicalAddr rootTable() {
		return _rootTable;
	}

	void retire(RetireNode *node);

	bool submitShootdown(ShootNode *node);

private:
	PhysicalAddr _rootTable;

	std::atomic<bool> _wantToRetire = false;

	RetireNode * _retireNode = nullptr;

	frg::ticket_spinlock _mutex;

	unsigned int _numBindings;

	uint64_t _shootSequence;

	frg::intrusive_list<
		ShootNode,
		frg::locate_member<
			ShootNode,
			frg::default_list_hook<ShootNode>,
			&ShootNode::_queueNode
		>
	> _shootQueue;
};

namespace page_mode {
	static constexpr uint32_t remap = 1;
}

enum class PageMode {
	null,
	normal,
	remap
};

using PageFlags = uint32_t;

namespace page_access {
	static constexpr uint32_t write = 1;
	static constexpr uint32_t execute = 2;
	static constexpr uint32_t read = 4;
}

using PageStatus = uint32_t;

namespace page_status {
	static constexpr PageStatus present = 1;
	static constexpr PageStatus dirty = 2;
};

enum class CachingMode {
	null,
	uncached,
	writeCombine,
	writeThrough,
	writeBack,
	mmio = uncached,
	mmioNonPosted = uncached
};

struct KernelPageSpace {
	friend struct GlobalPageBinding;
public:
	static void initialize();

	static KernelPageSpace &global();

	// TODO: This should be private.
	explicit KernelPageSpace(PhysicalAddr pml4_address);

	KernelPageSpace(const KernelPageSpace &) = delete;

	KernelPageSpace &operator= (const KernelPageSpace &) = delete;

	PhysicalAddr rootTable() {
		return _rootTable;
	}

	bool submitShootdown(ShootNode *node);

	void mapSingle4k(VirtualAddr pointer, PhysicalAddr physical,
			uint32_t flags, CachingMode caching_mode);
	PhysicalAddr unmapSingle4k(VirtualAddr pointer);

private:
	PhysicalAddr _rootTable;

	frg::ticket_spinlock _mutex;

	frg::ticket_spinlock _shootMutex;

	unsigned int _numBindings;

	uint64_t _shootSequence;

	frg::intrusive_list<
		ShootNode,
		frg::locate_member<
			ShootNode,
			frg::default_list_hook<ShootNode>,
			&ShootNode::_queueNode
		>
	> _shootQueue;
};

constexpr uint64_t ptePresent = 0x1;
constexpr uint64_t pteWrite = 0x2;
constexpr uint64_t pteUser = 0x4;
constexpr uint64_t ptePwt = 0x8;
constexpr uint64_t ptePcd = 0x10;
constexpr uint64_t pteDirty = 0x40;
constexpr uint64_t ptePat = 0x80;
constexpr uint64_t pteGlobal = 0x100;
constexpr uint64_t pteXd = 0x8000000000000000;
constexpr uint64_t pteAddress = 0x000FFFFFFFFFF00;

struct ClientPageSpace : PageSpace {
public:
	struct Walk {
		Walk(ClientPageSpace *space);

		Walk(const Walk &) = delete;

		~Walk();

		Walk &operator= (const Walk &) = delete;

		void walkTo(uintptr_t address);

		PageFlags peekFlags();
		PhysicalAddr peekPhysical();

	private:
		ClientPageSpace *_space;

		void _update();

		uintptr_t _address = 0;

		// Accessors for all levels of PTs.
		PageAccessor _accessor4; // Coarsest level (PML4).
		PageAccessor _accessor3;
		PageAccessor _accessor2;
		PageAccessor _accessor1; // Finest level (page table).
	};

	struct Cursor {
		Cursor(ClientPageSpace *space, uintptr_t va)
		: space_{space}, va_{0} {
			_accessor4 = PageAccessor{space->rootTable()};
			moveTo(va);
		}

		uintptr_t virtualAddress() {
			return va_;
		}

		void moveTo(uintptr_t va) {
			if((va_ ^ va) & (uintptr_t{0x1FF} << 39)) {
				_accessor3 = {};
				_accessor2 = {};
				_accessor1 = {};
			}else if((va_ ^ va) & (uintptr_t{0x1FF} << 30)) {
				_accessor2 = {};
				_accessor1 = {};
			}else if((va_ ^ va) & (uintptr_t{0x1FF} << 21)) {
				_accessor1 = {};
			}
			va_ = va;
			accessPts();
		}

		void advance4k() {
			moveTo(va_ + kPageSize);
		}

		bool findPresent(uintptr_t limit) {
			while(va_ < limit) {
				if(!_accessor1) {
					advance4k();
					continue;
				}
				auto ptPtr = reinterpret_cast<uint64_t *>(_accessor1.get())
						+ ((va_ >> 12) & 0x1FF);
				auto ptEnt = __atomic_load_n(ptPtr, __ATOMIC_RELAXED);
				if(ptEnt & ptePresent)
					return true;
				advance4k();
			}
			return false;
		}

		bool findDirty(uintptr_t limit) {
			while(va_ < limit) {
				if(!_accessor1) {
					advance4k();
					continue;
				}
				auto ptPtr = reinterpret_cast<uint64_t *>(_accessor1.get())
						+ ((va_ >> 12) & 0x1FF);
				auto ptEnt = __atomic_load_n(ptPtr, __ATOMIC_RELAXED);
				if((ptEnt & ptePresent) && (ptEnt & pteDirty))
					return true;
				advance4k();
			}
			return false;
		}

		void map4k(PhysicalAddr pa, PageFlags flags, CachingMode cachingMode) {
			if(!_accessor1)
				realizePts();

			auto ptPtr = reinterpret_cast<uint64_t *>(_accessor1.get())
					+ ((va_ >> 12) & 0x1FF);
			auto ptEnt = __atomic_load_n(ptPtr, __ATOMIC_RELAXED);
			assert(!(ptEnt & ptePresent));

			ptEnt = pa | ptePresent | pteUser;
			if(flags & page_access::write)
				ptEnt |= pteWrite;
			if(!(flags & page_access::execute))
				ptEnt |= pteXd;
			if(cachingMode == CachingMode::writeThrough) {
				ptEnt |= ptePwt;
			}else if(cachingMode == CachingMode::writeCombine) {
				ptEnt |= ptePat | ptePwt;
			}else if(cachingMode == CachingMode::uncached) {
				ptEnt |= ptePcd;
			}else{
				assert(cachingMode == CachingMode::null || cachingMode == CachingMode::writeBack);
			}
			__atomic_store_n(ptPtr, ptEnt, __ATOMIC_RELAXED);
		}

		PageStatus remap4k(PhysicalAddr pa, PageFlags flags, CachingMode cachingMode) {
			if(!_accessor1)
				realizePts();

			auto ptPtr = reinterpret_cast<uint64_t *>(_accessor1.get())
					+ ((va_ >> 12) & 0x1FF);
			auto ptEnt = pa | ptePresent | pteUser;
			if(flags & page_access::write)
				ptEnt |= pteWrite;
			if(!(flags & page_access::execute))
				ptEnt |= pteXd;
			if(cachingMode == CachingMode::writeThrough) {
				ptEnt |= ptePwt;
			}else if(cachingMode == CachingMode::writeCombine) {
				ptEnt |= ptePat | ptePwt;
			}else if(cachingMode == CachingMode::uncached) {
				ptEnt |= ptePcd;
			}else{
				assert(cachingMode == CachingMode::null || cachingMode == CachingMode::writeBack);
			}
			ptEnt = __atomic_exchange_n(ptPtr, ptEnt, __ATOMIC_RELAXED);
			if(!(ptEnt & ptePresent))
				return 0;
			PageStatus status = page_status::present;
			if(ptEnt & pteDirty)
				status |= page_status::dirty;
			return status;
		}

		PageStatus clean4k() {
			if(!_accessor1)
				return 0;

			auto ptPtr = reinterpret_cast<uint64_t *>(_accessor1.get())
					+ ((va_ >> 12) & 0x1FF);
			auto ptEnt = __atomic_fetch_and(ptPtr, ~pteDirty, __ATOMIC_RELAXED);
			if(!(ptEnt & ptePresent))
				return 0;
			PageStatus status = page_status::present;
			if(ptEnt & pteDirty)
				status |= page_status::dirty;
			return status;
		}

		PageStatus unmap4k() {
			if(!_accessor1)
				return 0;

			auto ptPtr = reinterpret_cast<uint64_t *>(_accessor1.get())
					+ ((va_ >> 12) & 0x1FF);
			auto ptEnt = __atomic_exchange_n(ptPtr, 0, __ATOMIC_RELAXED);
			if(!(ptEnt & ptePresent))
				return 0;
			PageStatus status = page_status::present;
			if(ptEnt & pteDirty)
				status |= page_status::dirty;
			return status;
		}

	private:
		void accessPts() {
			auto doReload = [&] <int S> (PageAccessor &subPt, PageAccessor &pt,
					std::integral_constant<int, S>) -> bool {
				auto ptPtr = reinterpret_cast<uint64_t *>(pt.get())
						+ ((va_ >> S) & 0x1FF);
				auto ptEnt = __atomic_load_n(ptPtr, __ATOMIC_ACQUIRE);
				if(!(ptEnt & ptePresent))
					return false;
				subPt = PageAccessor{ptEnt & pteAddress};
				return true;
			};

			auto reload3 = [&] {
				if(_accessor3) /*[[likely]]*/
					return true;
				return doReload(_accessor3, _accessor4, std::integral_constant<int, 39>{});
			};
			auto reload2 = [&] {
				if(_accessor2) /*[[likely]]*/
					return true;
				if(!reload3())
					return false;
				return doReload(_accessor2, _accessor3, std::integral_constant<int, 30>{});
			};

			if(_accessor1) /*[[likely]]*/
				return;
			if(!reload2())
				return;
			doReload(_accessor1, _accessor2, std::integral_constant<int, 21>{});
		}

		void realizePts();

		ClientPageSpace *space_;

		uintptr_t va_ = 0;

		// Accessors for all levels of PTs.
		PageAccessor _accessor4; // Coarsest level (PML4).
		PageAccessor _accessor3;
		PageAccessor _accessor2;
		PageAccessor _accessor1; // Finest level (page table).
	};

	ClientPageSpace();

	ClientPageSpace(const ClientPageSpace &) = delete;

	~ClientPageSpace();

	ClientPageSpace &operator= (const ClientPageSpace &) = delete;

	void mapSingle4k(VirtualAddr pointer, PhysicalAddr physical, bool user_access,
			uint32_t flags, CachingMode caching_mode);
	PageStatus unmapSingle4k(VirtualAddr pointer);
	PageStatus cleanSingle4k(VirtualAddr pointer);
	bool isMapped(VirtualAddr pointer);
	bool updatePageAccess(VirtualAddr pointer);

private:
	frg::ticket_spinlock _mutex;
};

void invalidatePage(const void *address);

void invalidateFullTlb();

} // namespace thor
