// SPDX-License-Identifier: MIT

#include "shared_secret_database.hpp"

#include <securepath/util/conversions.hpp>

namespace securepath::crypto {

shared_secret_database::shared_secret_database(database::connection_ptr c)
: db_(std::move(c))
{
	if(!db_->has_table("secrets")) {
		db_->prepare("CREATE TABLE secrets(key TEXT PRIMARY KEY, data BLOB);").execute();
	}
}

void shared_secret_database::insert(octet_span const& k, octet_span const& d) {
	if(k.empty()) {
		throw invalid_secret_key_size();
	}
	auto q = db_->prepare("INSERT OR REPLACE INTO secrets VALUES(:k,:d)");
	q.bind(":k", to_hex(k));
	q.bind(":d", octet_vector(d.begin(), d.end()));
	q.execute();
}

void shared_secret_database::remove(octet_span const& k) {
	auto q = db_->prepare("DELETE FROM secrets WHERE key = :k");
	q.bind(":k", to_hex(k));
	q.execute();
}

std::optional<octet_vector> shared_secret_database::find(octet_span const& k) const {
	std::optional<octet_vector> ret;
	auto q = db_->prepare("SELECT data FROM secrets WHERE key = :k LIMIT 1");
	q.bind(":k", to_hex(k));
	auto res = q.execute();
	if(res) {
		ret = res.value<octet_vector>(0);
		if(!ret) {
			ret = octet_vector{};
		}
	}
	return ret;
}

}
