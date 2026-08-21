// SPDX-License-Identifier: MIT

#pragma once

#include "output.hpp"
#include <string>

namespace securepath::log::backend {

/**
 *	Adds output to basic backend
 */ 
void add(std::string name, output_ptr p);

/**
 *	Removes output from basic backend
 */
void remove(std::string const& name);

/**
 *	Logs message.
 *	Every backend added logs the message when this function is called.
 */
void log(formatted_message const&);

/**
 *  Returns the minimum log level of outputs added.
 */
int get_min_log_level();

/**
 *	
 */
template<typename Backend, typename... Args>
void add_backend(std::string name, Args&&... args) {
	add(std::move(name), std::make_unique<Backend>(std::forward<Args>(args)...));
}

}

