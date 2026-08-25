// SPDX-License-Identifier: MIT

#include "key_value_database.hpp"

namespace securepath {

key_value_database::key_value_database(database::connection_ptr db, std::string table, std::uint64_t key)
: db_(db)
, table_(std::move(table))
, selector_(key)
{
	if(!db_->has_table(table_)) {
		std::string prepare_str =
			"CREATE TABLE " + table_ + "("
				"key TEXT,"
				"data BLOB,"
				"selector INTEGER,"
				"PRIMARY KEY(key, selector));";
		db_->prepare(prepare_str).execute();
	}
}

void key_value_database::insert(key_type const& key, octet_vector const& data) {
	std::string s = "INSERT OR REPLACE INTO " + table_ + " VALUES(:k,:d,:s);";
	auto q = db_->prepare(s);
	q.bind(":k", key);
	q.bind(":d", data);
	q.bind(":s", selector_);
	q.execute();
}

std::optional<octet_vector> key_value_database::find(key_type const& key) const {
	std::string s = "SELECT data FROM " + table_ + " WHERE key = :k AND selector = :s";
	auto q = db_->prepare(s);
	q.bind(":k", key);
	q.bind(":s", selector_);

	auto res = q.execute();

	std::optional<octet_vector> v;
	if(res) {
		v = res.value<octet_vector>(0);
	}
	return v;
}

void key_value_database::erase(key_type const& key) {
	std::string s = "DELETE FROM " + table_ + " WHERE key = :k AND selector = :s";
	auto q = db_->prepare(s);
	q.bind(":k", key);
	q.bind(":s", selector_);
	q.execute();
}

void key_value_database::clear() {
	std::string s = "DELETE FROM " + table_ + " WHERE selector = :s";
	auto q = db_->prepare(s);
	q.bind(":s", selector_);
	q.execute();
}

}
