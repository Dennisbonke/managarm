#pragma once

#include "api.hpp"

#include <helix/ipc.hpp>

namespace protocols {
namespace usb {

Device connect(helix::UniqueLane lane);

}  // namespace usb
}  // namespace protocols
