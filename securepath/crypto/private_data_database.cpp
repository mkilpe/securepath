// SPDX-License-Identifier: MIT

#include "private_data_database.hpp"

namespace securepath::crypto {

private_data_database::private_data_database(database::connection_ptr c)
: db_(std::move(c))
{
	if(!db_->has_table("private_data")) {
		db_->prepare("CREATE TABLE private_data(key TEXT PRIMARY KEY, data BLOB);").execute();
	}
}

std::optional<private_key> private_data_database::my_private_key() const {
	return find<private_key>("__private_key");
}

void private_data_database::set_my_private_key(private_key const& key) {
	insert("__private_key", key);
}

std::optional<certificate_chain> private_data_database::my_certificate_chain() const {
	return find<certificate_chain>("__certificate_chain");
}

void private_data_database::set_my_certificate_chain(certificate_chain const& chain) {
	insert("__certificate_chain", chain);
}

void private_data_database::insert(key_type const& key, octet_vector data) {
	auto q = db_->prepare("INSERT OR REPLACE INTO private_data VALUES(:k,:d);");
	q.bind(":k", key);
	q.bind(":d", data);
	q.execute();
}

std::optional<octet_vector> private_data_database::find(key_type const& key) const {
	auto q = db_->prepare("SELECT data FROM private_data WHERE key = :k");
	q.bind(":k", key);
	auto res = q.execute();
	std::optional<octet_vector> v;
	if(res) {
		v = res.value<octet_vector>(0);
	}
	return v;
}

void private_data_database::erase(key_type const& key) {
	auto q = db_->prepare("DELETE FROM private_data WHERE key = :k");
	q.bind(":k", key);
	q.execute();
}

}
