// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/common/version_number.hpp>

namespace securepath {

inline version_number library_version() {
	return version_number{1, 0, 0, "alpha"};
}

}
