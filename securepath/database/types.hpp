// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>
#include <stdexcept>

namespace securepath::database {

struct database_error : std::runtime_error {
	using std::runtime_error::runtime_error;
	database_error() : std::runtime_error("") {}
};

}

