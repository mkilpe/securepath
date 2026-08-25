// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace securepath::database {

using time_point = std::chrono::time_point<std::chrono::system_clock>;

class query_impl;

class prepared_statement_impl {
public:
	virtual ~prepared_statement_impl() {}

	virtual void bind(std::string const&) = 0;
	virtual void bind(std::string const&, std::int64_t) = 0;
	virtual void bind(std::string const&, std::uint64_t) = 0;
	virtual void bind(std::string const&, std::string_view const&) = 0;
	virtual void bind(std::string const&, octet_vector const&) = 0;
	virtual void bind(std::string const&, time_point const&) = 0;
	virtual void reset() = 0;

	virtual std::unique_ptr<query_impl> execute() = 0;

	virtual std::int64_t last_inserted_row_id() const = 0;
};

class query_impl {
public:
	virtual ~query_impl() {}

	virtual bool next() = 0;
	virtual bool empty() const = 0;

	virtual bool value(std::size_t column, std::int64_t&) const = 0;
	virtual bool value(std::size_t column, std::uint64_t&) const = 0;
	virtual bool value(std::size_t column, std::string&) const = 0;
	virtual bool value(std::size_t column, octet_vector&) const = 0;
	virtual bool value(std::size_t column, time_point&) const = 0;
};

}

