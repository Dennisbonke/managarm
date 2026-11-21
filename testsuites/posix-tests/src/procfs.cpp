#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "testsuite.hpp"

DEFINE_TEST(procfs_status_after_wait, ([] {
	pid_t pid = fork();
	assert(pid >= 0);

	if(!pid) {
		_exit(0);
	}

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	int fd = open(path, O_RDONLY);
	assert(fd >= 0);

	char task_path[64];
	snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d/status", pid, pid);
	int task_fd = open(task_path, O_RDONLY);
	assert(task_fd >= 0);

	siginfo_t dummy;
	int ret = waitid(P_PID, pid, &dummy, WEXITED | WNOWAIT);
	assert(ret == 0);

	char buf[64];
	lseek(fd, 0, SEEK_SET);
	ret = read(fd, buf, sizeof(buf) - 1);
	assert(ret > 0);
	lseek(fd, 0, SEEK_SET);

	std::ifstream pid_stream{path};

	bool found_zombie_state = false;
	for (std::string line; std::getline(pid_stream, line); ) {
		if (line.starts_with("State:")) {
			found_zombie_state = true;
			assert(line == "State:\tZ (zombie)");
			break;
		}
	}
	assert(found_zombie_state);

	// Same check for the task status file.
	lseek(task_fd, 0, SEEK_SET);
	ret = read(task_fd, buf, sizeof(buf) - 1);
	assert(ret > 0);
	lseek(task_fd, 0, SEEK_SET);

	std::ifstream tid_stream{task_path};
	found_zombie_state = false;
	for (std::string line; std::getline(tid_stream, line); ) {
		if (line.starts_with("State:")) {
			found_zombie_state = true;
			assert(line == "State:\tZ (zombie)");
			break;
		}
	}
	assert(found_zombie_state);

	int status;
	ret = waitpid(pid, &status, 0);
	assert(ret == pid);

	ret = read(fd, buf, sizeof(buf));
	assert(ret == -1);
	assert(errno == ESRCH);

	ret = read(task_fd, buf, sizeof(buf));
	assert(ret == -1);
	assert(errno == ESRCH);

	close(fd);
	close(task_fd);

	fd = open(path, O_RDONLY);
	assert(fd == -1);
	assert(errno == ENOENT);

	task_fd = open(task_path, O_RDONLY);
	assert(task_fd == -1);
	assert(errno == ENOENT);
}))

static void *thread_main(void *) {
	sleep(1);

	char task_path[64];
	snprintf(task_path, sizeof(task_path), "/proc/%d/task", getpid());
	std::filesystem::path task_dir{task_path};
	assert(std::filesystem::exists(task_dir));
	assert(std::filesystem::is_directory(task_dir));
	fprintf(stderr, "\t%s exists\n", task_path);

	snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d", getpid(), getpid());
	std::filesystem::path main_thread_path{task_path};
	assert(std::filesystem::exists(main_thread_path));
	assert(std::filesystem::is_directory(main_thread_path));
	fprintf(stderr, "\t%s exists\n", task_path);

	snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d", getpid(), gettid());
	std::filesystem::path thread_path{task_path};
	assert(std::filesystem::exists(thread_path));
	assert(std::filesystem::is_directory(thread_path));
	fprintf(stderr, "\t%s exists\n", task_path);

	pthread_exit(nullptr);
}

DEFINE_TEST(procfs_multithread_zombie, ([] {
	pid_t pid = fork();
	assert(pid >= 0);

	if(!pid) {
		pthread_t thread;
		int ret = pthread_create(&thread, nullptr, &thread_main, nullptr);
		assert(ret == 0);

		pthread_exit(nullptr);
	}

	siginfo_t dummy;
	int ret = waitid(P_PID, pid, &dummy, WEXITED | WNOWAIT);
	assert(ret == 0);

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	std::ifstream stream{path};
	assert(stream.good());

	bool found_zombie_state = false;
	for (std::string line; std::getline(stream, line); ) {
		if (line.starts_with("State:")) {
			found_zombie_state = true;
			assert(line == "State:\tZ (zombie)");
			break;
		}
	}
	assert(found_zombie_state);

	char task_path[64];
	snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d/status", pid, pid);
	std::ifstream task_stream{task_path};
	assert(task_stream.good());

	found_zombie_state = false;
	for (std::string line; std::getline(task_stream, line); ) {
		if (line.starts_with("State:")) {
			found_zombie_state = true;
			assert(line == "State:\tZ (zombie)");
			break;
		}
	}
	assert(found_zombie_state);

	int status;
	ret = waitpid(pid, &status, 0);
	assert(ret == pid);
}))

DEFINE_TEST(procfs_fd_directory_size, ([] {
	int directory = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
	assert(directory >= 0);

	struct stat before;
	const auto beforeResult = fstat(directory, &before);
	assert(beforeResult == 0);
	assert(before.st_size >= 1);

	int fd = dup(directory);
	assert(fd >= 0);
	struct stat afterOpen;
	const auto afterOpenResult = fstat(directory, &afterOpen);
	assert(afterOpenResult == 0);
	assert(afterOpen.st_size == before.st_size + 1);

	const auto closeResult = close(fd);
	assert(closeResult == 0);
	struct stat afterClose;
	const auto afterCloseResult = fstat(directory, &afterClose);
	assert(afterCloseResult == 0);
	assert(afterClose.st_size == before.st_size);
	close(directory);
}))

DEFINE_TEST(procfs_directory_stat_after_wait, ([] {
	// Global root ownership is translated through the caller's user namespace
	// by stat(), and may therefore be an overflow ID rather than numeric 0.
	struct stat rootOwner;
	const auto statResult = stat("/proc", &rootOwner);
	assert(statResult == 0);
	int sync[2];
	const auto pipeResult = pipe(sync);
	assert(pipeResult == 0);
	pid_t pid = fork();
	assert(pid >= 0);
	if(!pid) {
		close(sync[1]);
		char byte;
		const auto readResult = read(sync[0], &byte, 1);
		assert(readResult == 1);
		_exit(0);
	}
	close(sync[0]);

	const std::string base = "/proc/" + std::to_string(pid);
	const std::string paths[] = {
		base, base + "/task", base + "/task/" + std::to_string(pid),
		base + "/fd", base + "/fdinfo"
	};
	int fds[5];
	struct stat before[5];
	for(int i = 0; i < 5; ++i) {
		fds[i] = open(paths[i].c_str(), O_RDONLY | O_DIRECTORY);
		assert(fds[i] >= 0);
		const auto fstatResult = fstat(fds[i], &before[i]);
		assert(fstatResult == 0);
	}
	const auto writeResult = write(sync[1], "x", 1);
	assert(writeResult == 1);
	close(sync[1]);
	siginfo_t zombie;
	const auto waitIdResult = waitid(P_PID, pid, &zombie, WEXITED | WNOWAIT);
	assert(waitIdResult == 0);
	struct stat fdDirectory;
	const auto fstatResult = fstat(fds[3], &fdDirectory);
	assert(fstatResult == 0);
	assert(S_ISDIR(fdDirectory.st_mode));
	assert(fdDirectory.st_size == 0);
	int status;
	const auto waitPidResult = waitpid(pid, &status, 0);
	assert(waitPidResult == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	for(int i = 0; i < 5; ++i) {
		struct stat after;
		if(i == 3) { // The fd directory disappears only once the child is reaped.
			errno = 0;
			const auto fstatResult2 = fstat(fds[i], &after);
			assert(fstatResult2 == -1);
			assert(errno == ENOENT);
			close(fds[i]);
			continue;
		}
		const auto fstatResult2 = fstat(fds[i], &after);
		assert(fstatResult2 == 0);
		assert(after.st_mode == before[i].st_mode);
		assert(after.st_ino == before[i].st_ino);
		if(i == 0 || i == 2) { // PID and TID use pid_getattr's root fallback.
			assert(after.st_uid == rootOwner.st_uid && after.st_gid == rootOwner.st_gid);
		} else { // task and fdinfo retain their inode's ownership.
			assert(after.st_uid == before[i].st_uid && after.st_gid == before[i].st_gid);
		}
		assert(after.st_mtim.tv_sec == before[i].st_mtim.tv_sec);
		assert(after.st_mtim.tv_nsec == before[i].st_mtim.tv_nsec);
		close(fds[i]);
	}
}))

DEFINE_TEST(procfs_dumpability_inherited_on_fork, ([] {
	pid_t child = fork();
	assert(child >= 0);
	if(!child) {
		const auto setDumpableResult = prctl(PR_SET_DUMPABLE, 0);
		assert(setDumpableResult == 0);
		// Compare with the parent's non-dumpable ownership, already translated
		// through this user namespace (unmapped root can appear as 65534).
		struct stat nondumpableOwner;
		const auto statResult = stat("/proc/self/status", &nondumpableOwner);
		assert(statResult == 0);
		pid_t grandchild = fork();
		assert(grandchild >= 0);
		if(!grandchild) {
			const auto getDumpableResult = prctl(PR_GET_DUMPABLE);
			assert(getDumpableResult == 0);
			struct stat stats;
			const auto statResult2 = stat("/proc/self/status", &stats);
			assert(statResult2 == 0);
			assert(stats.st_uid == nondumpableOwner.st_uid);
			assert(stats.st_gid == nondumpableOwner.st_gid);
			const auto statResult3 = stat("/proc/self", &stats);
			assert(statResult3 == 0);
			assert(stats.st_uid == geteuid() && stats.st_gid == getegid());
			const auto setDumpableResult2 = prctl(PR_SET_DUMPABLE, 1);
			assert(setDumpableResult2 == 0);
			const auto statResult4 = stat("/proc/self/status", &stats);
			assert(statResult4 == 0);
			assert(stats.st_uid == geteuid() && stats.st_gid == getegid());
			_exit(0);
		}
		int status;
		const auto waitPidResult = waitpid(grandchild, &status, 0);
		assert(waitPidResult == grandchild);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		_exit(0);
	}
	int status;
	const auto waitPidResult = waitpid(child, &status, 0);
	assert(waitPidResult == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}))

DEFINE_TEST(procfs_lookup_refreshes_retained_directory_owner, ([] {
	if(geteuid() != 0 || getegid() == 1)
		skip_test("requires root and a different effective GID");

	int ready[2], finish[2];
	const auto readyResult = pipe(ready);
	assert(readyResult == 0);
	const auto finishResult = pipe(finish);
	assert(finishResult == 0);
	pid_t pid = fork();
	assert(pid >= 0);
	if(!pid) {
		close(ready[0]);
		close(finish[1]);
		const auto gidResult = setegid(1);
		const bool changed = gidResult == 0;
		const auto writeResult = write(ready[1], &changed, sizeof(changed));
		assert(writeResult == sizeof(changed));
		if(changed) {
			char byte;
			const auto readResult = read(finish[0], &byte, 1);
			assert(readResult == 1);
		}
		_exit(0);
	}
	close(ready[1]);
	close(finish[0]);
	bool changed;
	const auto readResult = read(ready[0], &changed, sizeof(changed));
	assert(readResult == sizeof(changed));
	close(ready[0]);

	int task = -1, fdinfo = -1;
	if(changed) {
		const auto base = "/proc/" + std::to_string(pid);
		task = open((base + "/task").c_str(), O_PATH | O_DIRECTORY);
		assert(task >= 0);
		fdinfo = open((base + "/fdinfo").c_str(), O_PATH | O_DIRECTORY);
		assert(fdinfo >= 0);
		const auto writeResult = write(finish[1], "x", 1);
		assert(writeResult == 1);
	}
	close(finish[1]);
	int status;
	const auto waitResult = waitpid(pid, &status, 0);
	assert(waitResult == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	if(!changed)
		skip_test("requires permission to set effective GID 1");

	for(int fd : {task, fdinfo}) {
		struct stat stats;
		const auto statResult = fstat(fd, &stats);
		assert(statResult == 0);
		assert(stats.st_gid == 1);
		close(fd);
	}
}))
