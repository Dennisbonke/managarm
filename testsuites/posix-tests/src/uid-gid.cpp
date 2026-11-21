#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstdint>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>

#include "testsuite.hpp"

namespace {

struct UidState {
	uid_t real;
	uid_t effective;
	uid_t saved;
};

struct GidState {
	gid_t real;
	gid_t effective;
	gid_t saved;
};

UidState get_uid_state() {
	UidState state;
	const auto getResuidResult = getresuid(&state.real, &state.effective, &state.saved);
	assert(getResuidResult == 0);
	return state;
}

GidState get_gid_state() {
	GidState state;
	const auto getResgidResult = getresgid(&state.real, &state.effective, &state.saved);
	assert(getResgidResult == 0);
	return state;
}

void assert_uid_state(const UidState &expected) {
	const auto actual = get_uid_state();
	assert(actual.real == expected.real);
	assert(actual.effective == expected.effective);
	assert(actual.saved == expected.saved);
}

void assert_gid_state(const GidState &expected) {
	const auto actual = get_gid_state();
	assert(actual.real == expected.real);
	assert(actual.effective == expected.effective);
	assert(actual.saved == expected.saved);
}

bool id_is_mapped(const char *path, uint64_t id) {
	FILE *file = fopen(path, "r");
	if(!file)
		return true;

	bool haveMapping = false;
	bool mapped = false;
	unsigned long long first;
	unsigned long long second;
	unsigned long long count;
	while(fscanf(file, "%llu %llu %llu", &first, &second, &count) == 3) {
		haveMapping = true;
		if(id >= first && id - first < count)
			mapped = true;
	}
	fclose(file);

	// Systems without user namespaces need not provide these files. An empty
	// file is treated the same way, since it does not describe a restriction.
	return !haveMapping || mapped;
}

template<typename Id>
bool choose_other(const char *mapPath, Id first, Id second, Id third, Id &result) {
	const Id candidates[] = {
		static_cast<Id>(65534), static_cast<Id>(65533),
		static_cast<Id>(1000), static_cast<Id>(1001),
		static_cast<Id>(1), static_cast<Id>(2)
	};
	for(auto candidate : candidates) {
		if(candidate != first && candidate != second && candidate != third
				&& id_is_mapped(mapPath, static_cast<uint64_t>(candidate))) {
			result = candidate;
			return true;
		}
	}

	// Do not scan the whole ID space: a rootless user namespace may map only
	// one ID, while a normal namespace accepts the candidates above.
	return false;
}

template<typename Id>
constexpr Id no_change_id() {
	return static_cast<Id>(-1);
}

void assert_permission_failure(int result) {
	assert(result == -1);
	assert(errno == EPERM);
}

void check_retained_procfs_directory_owner(int flags) {
	if(geteuid() != 0)
		skip_test("requires effective UID 0");
	uid_t otherUid;
	gid_t otherGid;
	const auto beforeGid = get_gid_state();
	if(!choose_other("/proc/self/uid_map", uid_t{0}, uid_t{0}, uid_t{0}, otherUid)
			|| !choose_other("/proc/self/gid_map", beforeGid.real, beforeGid.effective,
				beforeGid.saved, otherGid))
		skip_test("requires alternative mapped UID and GID");

	int ready[2];
	int release[2];
	const auto pipeResult = pipe(ready);
	assert(pipeResult == 0);
	const auto pipeResult2 = pipe(release);
	assert(pipeResult2 == 0);
	pid_t child = fork();
	assert(child >= 0);
	if(!child) {
		close(ready[0]);
		close(release[1]);
		const auto setResgidResult = setresgid(beforeGid.real, otherGid, beforeGid.saved);
		assert(setResgidResult == 0);
		const auto setResuidResult = setresuid(0, otherUid, 0);
		assert(setResuidResult == 0);
		const auto writeResult = write(ready[1], "x", 1);
		assert(writeResult == 1);
		char byte;
		const auto readResult = read(release[0], &byte, 1);
		assert(readResult == 1);
		_exit(EXIT_SUCCESS);
	}
	close(ready[1]);
	close(release[0]);
	char byte;
	const auto readResult = read(ready[0], &byte, 1);
	assert(readResult == 1);
	close(ready[0]);

	const auto base = "/proc/" + std::to_string(child);
	const std::string paths[] = {base + "/task", base + "/fdinfo"};
	int fds[2];
	for(int i = 0; i < 2; ++i) {
		// Do not stat these inodes until after reaping: lookup/open itself
		// must update their retained ownership from the child's current IDs.
		fds[i] = open(paths[i].c_str(), flags | O_DIRECTORY);
		assert(fds[i] >= 0);
	}
	const auto writeResult = write(release[1], "x", 1);
	assert(writeResult == 1);
	close(release[1]);
	int status;
	const auto waitPidResult = waitpid(child, &status, 0);
	assert(waitPidResult == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
	for(auto fd : fds) {
		struct stat stats;
		const auto fstatResult = fstat(fd, &stats);
		assert(fstatResult == 0);
		assert(stats.st_uid == otherUid);
		assert(stats.st_gid == otherGid);
		const auto closeResult = close(fd);
		assert(closeResult == 0);
	}
}

template<typename F>
void run_in_child(F &&function) {
	pid_t child = fork();
	assert(child >= 0);
	if(!child) {
		function();
		_exit(EXIT_SUCCESS);
	}

	int status;
	const auto waitResult = waitpid(child, &status, 0);
	assert(waitResult == child);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == EXIT_SUCCESS);
}

} // namespace

DEFINE_TEST(getresuid, ([] {
	const auto state = get_uid_state();
	const auto real = getuid();
	const auto effective = geteuid();
	assert(state.real == real);
	assert(state.effective == effective);
}))

DEFINE_TEST(getresgid, ([] {
	const auto state = get_gid_state();
	const auto real = getgid();
	const auto effective = getegid();
	assert(state.real == real);
	assert(state.effective == effective);
}))

DEFINE_TEST(procfs_directory_owner_retained_on_open, ([] {
	check_retained_procfs_directory_owner(O_RDONLY);
}))

DEFINE_TEST(procfs_directory_owner_retained_on_lookup, ([] {
	// O_PATH bypasses the node's open implementation, so lookup must refresh it.
	check_retained_procfs_directory_owner(O_PATH);
}))

DEFINE_TEST(exec_resets_dumpability, ([] {
	constexpr char reexec[] = "POSIX_TEST_EXEC_RESETS_DUMPABILITY";
	if(getenv(reexec)) {
		assert(prctl(PR_GET_DUMPABLE) == 1);
		return;
	}
	if(getuid() != geteuid() || getgid() != getegid())
		skip_test("requires matching real and effective IDs");

	run_in_child([&] {
		assert(prctl(PR_SET_DUMPABLE, 0L) == 0);
		assert(prctl(PR_GET_DUMPABLE) == 0);
		assert(setenv(reexec, "1", 1) == 0);
		execl("/proc/self/exe", "posix-tests", "exec_resets_dumpability", nullptr);
		perror("execl");
		_exit(EXIT_FAILURE);
	});
}))

DEFINE_TEST(effective_ids_reset_dumpability, ([] {
	const auto beforeUid = get_uid_state();
	const auto beforeGid = get_gid_state();
	if(beforeUid.effective != 0)
		skip_test("requires effective UID 0");
	uid_t otherUid;
	gid_t otherGid;
	if(!choose_other("/proc/self/uid_map", beforeUid.real, beforeUid.effective,
			beforeUid.saved, otherUid)
			|| !choose_other("/proc/self/gid_map", beforeGid.real, beforeGid.effective,
				beforeGid.saved, otherGid))
		skip_test("no alternative mapped IDs");

	run_in_child([=] {
		const auto setDumpableResult = prctl(PR_SET_DUMPABLE, 1L);
		assert(setDumpableResult == 0);
		const auto sameGid = setresgid(no_change_id<gid_t>(), beforeGid.effective,
				no_change_id<gid_t>());
		assert(sameGid == 0);
		const auto getDumpableResult = prctl(PR_GET_DUMPABLE);
		assert(getDumpableResult == 1);
		const auto changeGid = setresgid(no_change_id<gid_t>(), otherGid,
				no_change_id<gid_t>());
		assert(changeGid == 0);
		const auto getDumpableResult2 = prctl(PR_GET_DUMPABLE);
		assert(getDumpableResult2 == 0);

		const auto setDumpableResult2 = prctl(PR_SET_DUMPABLE, 1L);
		assert(setDumpableResult2 == 0);
		const auto changeUid = setresuid(no_change_id<uid_t>(), otherUid,
				no_change_id<uid_t>());
		assert(changeUid == 0);
		const auto getDumpableResult3 = prctl(PR_GET_DUMPABLE);
		assert(getDumpableResult3 == 0);
		const auto setDumpableResult3 = prctl(PR_SET_DUMPABLE, 1L);
		assert(setDumpableResult3 == 0);
		const auto sameUid = setresuid(no_change_id<uid_t>(), otherUid,
				no_change_id<uid_t>());
		assert(sameUid == 0);
		const auto getDumpableResult4 = prctl(PR_GET_DUMPABLE);
		assert(getDumpableResult4 == 1);
	});
}))

DEFINE_TEST(setuid_drops_saved_uid, ([] {
	const auto before = get_uid_state();
	if(before.effective != 0)
		skip_test("requires effective UID 0");

	uid_t other;
	if(!choose_other("/proc/self/uid_map", before.real, before.effective,
			before.saved, other))
		skip_test("no alternative mapped UID");

	run_in_child([=] {
		const auto setUidResult = setuid(other);
		assert(setUidResult == 0);
		assert_uid_state({other, other, other});
		errno = 0;
		const auto setReuidResult = setreuid(no_change_id<uid_t>(), 0);
		assert_permission_failure(setReuidResult);
		assert_uid_state({other, other, other});
	});
}))

DEFINE_TEST(setgid_drops_saved_gid, ([] {
	const auto before = get_gid_state();
	const auto uidState = get_uid_state();
	if(uidState.effective != 0)
		skip_test("requires effective UID 0");

	gid_t other;
	if(!choose_other("/proc/self/gid_map", before.real, before.effective,
			before.saved, other))
		skip_test("no alternative mapped GID");
	uid_t dropUid;
	if(!choose_other("/proc/self/uid_map", uidState.real, uidState.effective,
			uidState.saved, dropUid))
		skip_test("no alternative mapped UID");

	run_in_child([=] {
		const auto setGidResult = setgid(other);
		assert(setGidResult == 0);
		assert_gid_state({other, other, other});
		const auto setUidResult = setuid(dropUid);
		assert(setUidResult == 0);
		errno = 0;
		const auto setRegidResult = setregid(no_change_id<gid_t>(), 0);
		assert_permission_failure(setRegidResult);
		assert_gid_state({other, other, other});
	});
}))

DEFINE_TEST(setreuid, ([] {
	const auto before = get_uid_state();
	uid_t other;
	if(!choose_other("/proc/self/uid_map", before.real, before.effective,
			before.saved, other))
		skip_test("no alternative mapped UID");

	const bool privileged = before.real == 0 || before.effective == 0;
	run_in_child([=] {
		const auto noChangeResult = setreuid(no_change_id<uid_t>(), no_change_id<uid_t>());
		assert(noChangeResult == 0);
		assert_uid_state(before);

		if(privileged) {
			const auto setReuidResult = setreuid(other, other);
			assert(setReuidResult == 0);
			const auto after = get_uid_state();
			assert(after.real == other);
			assert(after.effective == other);
			assert(after.saved == other);
		} else {
			errno = 0;
			const auto setReuidResult = setreuid(other, no_change_id<uid_t>());
			assert_permission_failure(setReuidResult);
			assert_uid_state(before);
		}
	});
}))

DEFINE_TEST(setregid, ([] {
	const auto before = get_gid_state();
	const auto uidState = get_uid_state();
	gid_t other;
	if(!choose_other("/proc/self/gid_map", before.real, before.effective,
			before.saved, other))
		skip_test("no alternative mapped GID");

	const bool privileged = uidState.real == 0 || uidState.effective == 0;
	run_in_child([=] {
		const auto noChangeResult = setregid(no_change_id<gid_t>(), no_change_id<gid_t>());
		assert(noChangeResult == 0);
		assert_gid_state(before);

		if(privileged) {
			const auto setRegidResult = setregid(other, other);
			assert(setRegidResult == 0);
			const auto after = get_gid_state();
			assert(after.real == other);
			assert(after.effective == other);
			assert(after.saved == other);
		} else {
			errno = 0;
			const auto setRegidResult = setregid(other, no_change_id<gid_t>());
			assert_permission_failure(setRegidResult);
			assert_gid_state(before);
		}
	});
}))

DEFINE_TEST(setresuid, ([] {
	const auto before = get_uid_state();
	uid_t other;
	if(!choose_other("/proc/self/uid_map", before.real, before.effective,
			before.saved, other))
		skip_test("no alternative mapped UID");

	const bool privileged = before.real == 0 || before.effective == 0;
	run_in_child([=] {
		const auto noChangeResult = setresuid(no_change_id<uid_t>(), no_change_id<uid_t>(),
				no_change_id<uid_t>());
		assert(noChangeResult == 0);
		assert_uid_state(before);

		if(privileged) {
			if(before.effective == 0) {
				const auto dropEuidResult = setresuid(no_change_id<uid_t>(), other,
						no_change_id<uid_t>());
				assert(dropEuidResult == 0);
				assert_uid_state({before.real, other, before.saved});
				const auto restoreEuidResult = setresuid(no_change_id<uid_t>(), 0,
						no_change_id<uid_t>());
				assert(restoreEuidResult == 0);
				assert_uid_state(before);
			}

			const auto setResuidResult = setresuid(other, other, other);
			assert(setResuidResult == 0);
			const auto after = get_uid_state();
			assert(after.real == other);
			assert(after.effective == other);
			assert(after.saved == other);
		} else {
			const auto noOpResult = setresuid(before.real, before.effective, before.saved);
			assert(noOpResult == 0);
			assert_uid_state(before);

			errno = 0;
			const auto setResuidResult = setresuid(other, no_change_id<uid_t>(),
					no_change_id<uid_t>());
			assert_permission_failure(setResuidResult);
			assert_uid_state(before);
		}
	});
}))

DEFINE_TEST(setresgid, ([] {
	const auto before = get_gid_state();
	const auto uidState = get_uid_state();
	gid_t other;
	if(!choose_other("/proc/self/gid_map", before.real, before.effective,
			before.saved, other))
		skip_test("no alternative mapped GID");

	const bool privileged = uidState.real == 0 || uidState.effective == 0;
	run_in_child([=] {
		const auto noChangeResult = setresgid(no_change_id<gid_t>(), no_change_id<gid_t>(),
				no_change_id<gid_t>());
		assert(noChangeResult == 0);
		assert_gid_state(before);

		if(privileged) {
			const auto setResgidResult = setresgid(other, other, other);
			assert(setResgidResult == 0);
			const auto after = get_gid_state();
			assert(after.real == other);
			assert(after.effective == other);
			assert(after.saved == other);
		} else {
			const auto noOpResult = setresgid(before.real, before.effective, before.saved);
			assert(noOpResult == 0);
			assert_gid_state(before);

			errno = 0;
			const auto setResgidResult = setresgid(other, no_change_id<gid_t>(),
					no_change_id<gid_t>());
			assert_permission_failure(setResgidResult);
			assert_gid_state(before);
		}
	});
}))
