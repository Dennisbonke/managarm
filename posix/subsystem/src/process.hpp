
#ifndef POSIX_SUBSYSTEM_PROCESS_HPP
#define POSIX_SUBSYSTEM_PROCESS_HPP

#include <memory>
#include <unordered_map>

#include "vfs.hpp"

typedef int ProcessId;

// TODO: This struct should store the process' VMAs once we implement them.
struct VmContext {
	static std::shared_ptr<VmContext> create();
	static std::shared_ptr<VmContext> clone(std::shared_ptr<VmContext> original);

	helix::BorrowedDescriptor getSpace() {
		return _space;
	}

private:
	helix::UniqueDescriptor _space;
};

struct FileContext {
	static std::shared_ptr<FileContext> create();
	static std::shared_ptr<FileContext> clone(std::shared_ptr<FileContext> original);

	helix::BorrowedDescriptor getUniverse() {
		return _universe;
	}
	
	helix::BorrowedDescriptor fileTableMemory() {
		return _fileTableMemory;
	}
	
	int attachFile(std::shared_ptr<File> file);

	void attachFile(int fd, std::shared_ptr<File> file);

	std::shared_ptr<File> getFile(int fd);

	void closeFile(int fd);

	HelHandle clientMbusLane() {
		return _clientMbusLane;
	}

private:
	helix::UniqueDescriptor _universe;

	// TODO: replace this by a tree that remembers gaps between keys.
	std::unordered_map<int, std::shared_ptr<File>> _fileTable;

	helix::UniqueDescriptor _fileTableMemory;

	HelHandle *_fileTableWindow;

	HelHandle _clientMbusLane;
};

struct Process {
	static cofiber::future<std::shared_ptr<Process>> init(std::string path);

	static std::shared_ptr<Process> fork(std::shared_ptr<Process> parent);

	static cofiber::future<void> exec(std::shared_ptr<Process> process,
			std::string path);

	std::shared_ptr<VmContext> vmContext() {
		return _vmContext;
	}
	
	std::shared_ptr<FileContext> fileContext() {
		return _fileContext;
	}

	void *clientFileTable() {
		return _clientFileTable;
	}

private:
	std::shared_ptr<VmContext> _vmContext;
	std::shared_ptr<FileContext> _fileContext;

	void *_clientFileTable;
};

#endif // POSIX_SUBSYSTEM_PROCESS_HPP

