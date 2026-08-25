// SPDX-License-Identifier: MIT

#include "connection.hpp"
#include <securepath/database/detail/connection.hpp>
#include <securepath/database/types.hpp>

#include <securepath/log/log.hpp>

#include <sqlite3.h>

#include <cassert>
#include <cstring>
#include <limits>

namespace securepath::database::sqlite {
namespace {
struct lock {
	lock(sqlite3* h)
	: mutex(sqlite3_db_mutex(h))
	{
		sqlite3_mutex_enter(mutex);
	}

	~lock() {
		sqlite3_mutex_leave(mutex);
	}

	sqlite3_mutex* mutex;
};
}

class sqlite_connection : public database::connection {
public:
	sqlite_connection(std::string const& file)
	: db_()
	{
		connect(file);
	}

	virtual ~sqlite_connection() {
		if(sqlite3_close(db_) != SQLITE_OK) {
			LOG_WARN("Failed to close database ({})", sqlite3_errmsg(db_));
		}
	}

	virtual prepared_statement prepare(std::string_view) override;
	virtual void begin_transaction() override;
	virtual void end_transaction(bool commit) override;

	virtual bool has_table(std::string_view) const override;

	void connect(std::string const& file) {
		int res = sqlite3_open_v2(file.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
		if(res != SQLITE_OK) {
			LOG_WARN("Failed to open database: {} ({})", file, sqlite3_errmsg(db_));
			throw database_error("Failed to open database: " + file);
		}
	}

	sqlite3* database_handle() const {
		return db_;
	}

private:
	sqlite3* db_;
};

connection_ptr create_sqlite_connection(std::string const& file) {
	return std::make_shared<sqlite_connection>(file);
}

void set_to_wal_mode(connection_ptr db) {
	db->prepare("PRAGMA journal_mode=WAL;").execute();
}

class sqlite_prepared_statement : public database::prepared_statement_impl {
public:
	sqlite_prepared_statement(sqlite3* db, std::string_view sql)
	: db_(db)
	, handle_()
	, last_inserted_()
	{
		lock l{db_};
		int res = sqlite3_prepare_v2(db_, sql.data(), sql.size(), &handle_, nullptr);
		if(res != SQLITE_OK) {
			LOG_WARN("Failed to create prepared statement ({})", sqlite3_errmsg(db_));
			throw database_error("Failed create prepared statement");
		}
		//LOG_INFO("prepared: {}", sql);
	}

	~sqlite_prepared_statement() {
		lock l{db_};
		if(sqlite3_finalize(handle_) != SQLITE_OK) {
			LOG_WARN("Failed to destroy prepared statement ({})", sqlite3_errmsg(db_));
		}
	}

	virtual void bind(std::string const&);
	virtual void bind(std::string const&, std::int64_t);
	virtual void bind(std::string const&, std::uint64_t);
	virtual void bind(std::string const&, std::string_view const&);
	virtual void bind(std::string const&, octet_vector const&);
	virtual void bind(std::string const&, time_point const&);
	virtual void reset();
	virtual std::unique_ptr<query_impl> execute();
	virtual std::int64_t last_inserted_row_id() const;

	int index(std::string const& name) const {
		int i = sqlite3_bind_parameter_index(handle_, name.c_str());
		if(!i) {
			LOG_WARN("prepared_statement: no such placeholder ({})", name);
			throw database_error("prepared_statement: no such placeholder");
		}
		return i;
	}

	bool step() {
		lock l{db_};
		int res = sqlite3_step(handle_);
		if(res != SQLITE_DONE && res != SQLITE_ROW) {
			LOG_WARN("Failed to step: {}", sqlite3_errmsg(db_));
			throw database_error("Failed to step");
		}
		else if(res == SQLITE_DONE) {
			last_inserted_ = sqlite3_last_insert_rowid(db_);
		}
		return res == SQLITE_ROW;
	}

	sqlite3_stmt* handle() const {
		return handle_;
	}

	std::int64_t last_inserted() const {
		return last_inserted_;
	}
private:
	sqlite3* db_;
	sqlite3_stmt* handle_;
	std::int64_t last_inserted_;
};

class sqlite_query : public database::query_impl {
public:
	sqlite_query(sqlite_prepared_statement& ps)
	: ps_(ps)
	, columns_(sqlite3_column_count(ps_.handle()))
	, has_value_(true)
	{
		assert(columns_);
	}

	virtual bool empty() const {
		return !has_value_;
	}

	virtual bool next() {
		if(has_value_) {
			has_value_ = ps_.step();
		}
		return has_value_;
	}

	virtual bool value(std::size_t column, std::int64_t&) const;
	virtual bool value(std::size_t column, std::uint64_t&) const;
	virtual bool value(std::size_t column, std::string&) const;
	virtual bool value(std::size_t column, octet_vector&) const;
	virtual bool value(std::size_t column, time_point&) const;


	sqlite3_stmt* handle() const {
		return ps_.handle();
	}

	int columns() const {
		return columns_;
	}
private:
	sqlite_prepared_statement& ps_;
	int columns_;
	bool has_value_;
};

prepared_statement sqlite_connection::prepare(std::string_view sql) {
	return prepared_statement(std::make_unique<sqlite_prepared_statement>(database_handle(), sql));
}

void sqlite_connection::begin_transaction() {
	prepare("SAVEPOINT securepath_transaction;").execute();
}

void sqlite_connection::end_transaction(bool commit) {
	if(commit) {
		prepare("RELEASE SAVEPOINT securepath_transaction;").execute();
	} else {
		prepare("ROLLBACK TO SAVEPOINT securepath_transaction;").execute();
	}
}

bool sqlite_connection::has_table(std::string_view table) const {
	auto s = prepared_statement(std::make_unique<sqlite_prepared_statement>(database_handle()
		, "SELECT name FROM sqlite_master WHERE type='table' AND name=:t;"));

	s.bind(":t", table);
	return static_cast<bool>(s.execute());
}

void sqlite_prepared_statement::bind(std::string const& name) {
	if(sqlite3_bind_null(handle(), index(name)) != SQLITE_OK) {
		LOG_WARN("prepared_statement: binding failed ({})", name);
		throw database_error("prepared_statement: binding failed");
	}
}

void sqlite_prepared_statement::bind(std::string const& name, std::int64_t v) {
	if(sqlite3_bind_int64(handle(), index(name), v) != SQLITE_OK) {
		LOG_WARN("prepared_statement: binding failed ({})", name);
		throw database_error("prepared_statement: binding failed");
	}
}

void sqlite_prepared_statement::bind(std::string const& name, std::uint64_t v) {
	std::int64_t sv = v + std::numeric_limits<std::int64_t>::min();
	bind(name, sv);
}

void sqlite_prepared_statement::bind(std::string const& name, std::string_view const& v) {
	if(sqlite3_bind_text(handle(), index(name), v.data(), v.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
		LOG_WARN("prepared_statement: binding failed ({})", name);
		throw database_error("prepared_statement: binding failed");
	}
}

void sqlite_prepared_statement::bind(std::string const& name, octet_vector const& v) {
	if(sqlite3_bind_blob(handle(), index(name), v.data(), v.size(), SQLITE_TRANSIENT) != SQLITE_OK) {
		LOG_WARN("prepared_statement: binding failed ({})", name);
		throw database_error("prepared_statement: binding failed");
	}
}

void sqlite_prepared_statement::bind(std::string const& name, time_point const& v) {
	std::int64_t since_epoch = time_point::clock::to_time_t(v);
	bind(name, since_epoch);
}

void sqlite_prepared_statement::reset() {
	sqlite3_reset(handle());
	sqlite3_clear_bindings(handle());
	last_inserted_ = 0;
}

std::unique_ptr<query_impl> sqlite_prepared_statement::execute() {
	return step() ? std::make_unique<sqlite_query>(*this) : nullptr;
}

std::int64_t sqlite_prepared_statement::last_inserted_row_id() const {
	return last_inserted();
}

bool sqlite_query::value(std::size_t column, std::int64_t& v) const {
	if(column >= static_cast<std::size_t>(columns())) {
		LOG_WARN("Invalid column index: {}", column);
		throw database_error("Invalid column index");
	}
	bool not_null = sqlite3_column_type(handle(), column) != SQLITE_NULL;
	if(not_null) {
		v = sqlite3_column_int64(handle(), column);
	}
	return not_null;
}

bool sqlite_query::value(std::size_t column, std::uint64_t& v) const {
	int64_t sv = 0;
	bool not_null = value(column, sv);
	if(not_null) {
		v = sv - std::numeric_limits<std::int64_t>::min();
	}
	return not_null;
}

bool sqlite_query::value(std::size_t column, std::string& v) const {
	if(column >= static_cast<std::size_t>(columns())) {
		LOG_WARN("Invalid column index: {}", column);
		throw database_error("Invalid column index");
	}
	unsigned char const* const p = sqlite3_column_text(handle(), column);
	if(p) {
		int size = sqlite3_column_bytes(handle(), column);
		v.resize(size);
		std::memcpy(&v[0], p, size);
	}
	return p;
}

bool sqlite_query::value(std::size_t column, octet_vector& v) const {
	if(column >= static_cast<std::size_t>(columns())) {
		LOG_WARN("Invalid column index: {}", column);
		throw database_error("Invalid column index");
	}
	void const* const p = sqlite3_column_blob(handle(), column);
	if(p) {
		int size = sqlite3_column_bytes(handle(), column);
		v.resize(size);
		std::memcpy(v.data(), p, size);
	}
	return p;
}

bool sqlite_query::value(std::size_t column, time_point& v) const {
	std::int64_t since_epoch = 0;
	bool not_null = value(column, since_epoch);
	if(not_null) {
		v = time_point::clock::from_time_t(since_epoch);
	}
	return not_null;
}

}
