// SPDX-License-Identifier: MIT

#include "connection.hpp"
#include "detail/connection.hpp"

#include <securepath/database/types.hpp>
#include <securepath/log/log.hpp>

namespace securepath::database {

transaction::transaction(connection& c)
: conn_(c)
, ex_count_(std::uncaught_exceptions())
{
	conn_.begin_transaction();
}

transaction::~transaction() {
	try {
		conn_.end_transaction(ex_count_ == std::uncaught_exceptions());
	} catch(database_error const& err) {
		LOG_WARN("failed to end transaction: {}", err.what());
	}
}

prepared_statement::prepared_statement(std::unique_ptr<prepared_statement_impl> impl)
: impl_(std::move(impl))
{
}

prepared_statement::prepared_statement(prepared_statement&&) = default;

prepared_statement::~prepared_statement() {

}

void prepared_statement::bind(std::string const& name) {
	impl_->bind(name);
}

void prepared_statement::bind(std::string const& name, std::int64_t v) {
	impl_->bind(name, v);
}

void prepared_statement::bind(std::string const& name, std::uint64_t v) {
	impl_->bind(name, v);
}

void prepared_statement::bind(std::string const& name, std::string_view const& v) {
	impl_->bind(name, v);
}

void prepared_statement::bind(std::string const& name, octet_vector const& v) {
	impl_->bind(name, v);
}

void prepared_statement::bind(std::string const& name, time_point const& v) {
	impl_->bind(name, v);
}

void prepared_statement::reset() {
	impl_->reset();
}

query prepared_statement::execute() & {
	return impl_->execute();
}

void prepared_statement::execute() && {
	impl_->execute();
}

std::int64_t prepared_statement::last_inserted_row_id() const {
	return impl_->last_inserted_row_id();
}

query::query(std::unique_ptr<query_impl> impl)
: impl_(std::move(impl))
{
}

query::query(query&&) = default;

query::~query() {

}

bool query::next() {
	return impl_->next();
}

bool query::empty() const {
	return !impl_ || impl_->empty();
}

bool query::value(std::size_t column, std::int64_t& v) const {
	return impl_->value(column, v);
}

bool query::value(std::size_t column, std::uint64_t& v) const {
	return impl_->value(column, v);
}

bool query::value(std::size_t column, std::string& v) const {
	return impl_->value(column, v);
}

bool query::value(std::size_t column, octet_vector& v) const {
	return impl_->value(column, v);
}

bool query::value(std::size_t column, time_point& v) const {
	return impl_->value(column, v);
}

}
