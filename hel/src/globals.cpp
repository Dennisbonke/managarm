
#include <helix/ipc.hpp>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace helix {

Dispatcher &Dispatcher::global() {
	thread_local static Dispatcher dispatcher;
	return dispatcher;
}

}  // namespace helix
