// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace securepath::database {

class prepared_statement;
class transaction;

class connection {
public:
	virtual ~connection() {}

	virtual prepared_statement prepare(std::string_view) = 0;

	virtual bool has_table(std::string_view) const = 0;

private:
	friend class transaction;

	virtual void begin_transaction() = 0;
	virtual void end_transaction(bool commit) = 0;
};

using connection_ptr = std::shared_ptr<connection>;

class transaction {
public:
	explicit transaction(connection& c);
	~transaction();

	transaction(transaction&&) = default;
	transaction(transaction const&) = delete;

private:
	connection& conn_;
	int ex_count_;
};

using time_point = std::chrono::time_point<std::chrono::system_clock>;
class prepared_statement_impl;
class query_impl;
class query;

class prepared_statement {
public:
	prepared_statement(std::unique_ptr<prepared_statement_impl>);
	prepared_statement(prepared_statement&&);
	~prepared_statement();

	void bind(std::string const&);
	void bind(std::string const&, std::int64_t);
	void bind(std::string const&, std::uint64_t);
	void bind(std::string const&, std::string_view const&);
	void bind(std::string const&, octet_vector const&);

	//this saves only in second precision, rewrite later if need be
	void bind(std::string const&, time_point const&);

	void reset();

	query execute() &;

	// this object itself needs to be alive when trying to access the query result
	// to we ban using the result if called for temporary
	void execute() &&;

	std::int64_t last_inserted_row_id() const;

private:
	friend class query_impl;
	friend class connection;
	std::unique_ptr<prepared_statement_impl> impl_;
};

class query {
public:
	query(std::unique_ptr<query_impl>);
	query(query&&);
	~query();

	bool next();
	bool empty() const;

	bool value(std::size_t column, std::int64_t&) const;
	bool value(std::size_t column, std::uint64_t&) const;
	bool value(std::size_t column, std::string&) const;
	bool value(std::size_t column, octet_vector&) const;

	//this saves only in second precision, rewrite later if need be
	bool value(std::size_t column, time_point&) const;

	template<typename T> std::optional<T> value(std::size_t c) const { T t{}; return value(c, t) ? std::optional<T>(t) : std::nullopt; }
	explicit operator bool() const { return !empty(); }
private:
	std::unique_ptr<query_impl> impl_;
};

}

