#pragma once

#include "api.hpp"

#include <async/result.hpp>
#include <helix/ipc.hpp>

namespace protocols {
namespace usb {

async::detached serve(Device device, helix::UniqueLane lane);

}  // namespace usb
}  // namespace protocols
