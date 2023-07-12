#include "inotify.hpp"

#include "fs.hpp"
#include "process.hpp"
#include "vfs.hpp"

#include <async/recurring-event.hpp>
#include <helix/ipc.hpp>
#include <iostream>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>

namespace inotify {

namespace {

struct OpenFile : File {
public:
	struct Packet {
		int descriptor;
		uint32_t events;
		std::string name;
		uint32_t cookie;
	};

	struct Watch final : FsObserver {
		Watch(OpenFile *file_, int descriptor, uint32_t mask)
		: file {file_}
		, descriptor {descriptor}
		, mask {mask} {}

		void observeNotification(uint32_t events, const std::string &name, uint32_t cookie)
			override {
			uint32_t inotifyEvents = 0;
			if(events & FsObserver::deleteEvent) {
				inotifyEvents |= IN_DELETE;
			}
			if(!(inotifyEvents & mask)) {
				return;
			}
			file->_queue.push_back(
				Packet {descriptor, inotifyEvents & mask, name, cookie}
			);
			file->_inSeq = ++file->_currentSeq;
			file->_statusBell.raise();
		}

		OpenFile *file;
		int descriptor;
		uint32_t mask;
	};

	static void serve(smarter::shared_ptr<OpenFile> file) {
		helix::UniqueLane lane;
		std::tie(lane, file->_passthrough) = helix::createStream();
		async::detach(protocols::fs::servePassthrough(
			std::move(lane),
			smarter::shared_ptr<File> {file},
			&File::fileOperations
		));
	}

	OpenFile() : File {StructName::get("inotify")} {}

	~OpenFile() {
		// TODO: Properly keep track of watches.
		std::cout << "\e[31m"
			     "posix: Destruction of inotify leaks watches"
			     "\e[39m"
			  << std::endl;
	}

	async::result<frg::expected<Error, size_t>>
	readSome(Process *, void *data, size_t maxLength) override {
		// TODO: As an optimization, we could return multiple events at the same time.
		Packet packet = std::move(_queue.front());
		_queue.pop_front();

		if(maxLength < sizeof(inotify_event) + packet.name.size() + 1) {
			co_return Error::illegalArguments;
		}

		inotify_event e;
		memset(&e, 0, sizeof(inotify_event));
		e.wd = packet.descriptor;
		e.mask = packet.events;
		e.cookie = packet.cookie;
		e.len = packet.name.size();

		memcpy(data, &e, sizeof(inotify_event));
		memcpy(reinterpret_cast<char *>(data) + sizeof(inotify_event),
		       packet.name.c_str(),
		       packet.name.size() + 1);
		co_return sizeof(inotify_event) + packet.name.size() + 1;
	}

	async::result<frg::expected<Error, PollWaitResult>>
	pollWait(Process *, uint64_t sequence, int mask, async::cancellation_token cancellation)
		override {
		(void) mask;  // TODO: utilize mask.
		// TODO: Return Error::fileClosed as appropriate.

		assert(sequence <= _currentSeq);
		while(sequence == _currentSeq && !cancellation.is_cancellation_requested()) {
			co_await _statusBell.async_wait(cancellation);
		}

		int edges = 0;
		if(_inSeq > sequence) {
			edges |= EPOLLIN;
		}

		co_return PollWaitResult(_currentSeq, edges);
	}

	async::result<frg::expected<Error, PollStatusResult>> pollStatus(Process *) override {
		int events = 0;
		if(!_queue.empty()) {
			events |= EPOLLIN;
		}

		co_return PollStatusResult(_currentSeq, events);
	}

	helix::BorrowedDescriptor getPassthroughLane() override { return _passthrough; }

	int addWatch(std::shared_ptr<FsNode> node, uint32_t mask) {
		// TODO: Coalesce watch descriptors for the same inode.
		if(mask & ~(IN_DELETE)) {
			std::cout << "posix: inotify mask " << mask << " is partially ignored"
				  << std::endl;
		}
		auto descriptor = _nextDescriptor++;
		auto watch = std::make_shared<Watch>(this, descriptor, mask);
		node->addObserver(watch);
		return descriptor;
	}

private:
	helix::UniqueLane _passthrough;
	std::deque<Packet> _queue;

	// TODO: Use a proper ID allocator to allocate watch descriptor IDs.
	int _nextDescriptor = 1;

	async::recurring_event _statusBell;
	uint64_t _currentSeq = 1;
	uint64_t _inSeq = 0;
};

}  // anonymous namespace

smarter::shared_ptr<File, FileHandle> createFile() {
	auto file = smarter::make_shared<OpenFile>();
	file->setupWeakFile(file);
	OpenFile::serve(file);
	return File::constructHandle(std::move(file));
}

int addWatch(File *base, std::shared_ptr<FsNode> node, uint32_t mask) {
	auto file = static_cast<OpenFile *>(base);
	return file->addWatch(std::move(node), mask);
}

}  // namespace inotify
