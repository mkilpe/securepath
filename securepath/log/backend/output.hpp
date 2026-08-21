// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/log/types.hpp>
#include <memory>

namespace securepath::log::backend {

/**
 *	\class output_base
 *	\brief Base class for outputs that can be added to backend.
 */
class output_base {
public:
	virtual ~output_base() {}

	virtual void log(formatted_message const& m) = 0;	
	virtual int get_min_log_level() const = 0;
};

using output_ptr = std::unique_ptr<output_base>;

}

