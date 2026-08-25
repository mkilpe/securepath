// SPDX-License-Identifier: MIT

#include "public_key_database.hpp"

#include <securepath/serialisation/util.hpp>

namespace securepath::crypto {

public_key_database::public_key_database(database::connection_ptr c)
: db_(std::move(c))
{
	if(!db_->has_table("public_keys")) {
		db_->prepare("CREATE TABLE public_keys(p_key_id TEXT PRIMARY KEY, data BLOB);").execute();
	}
}

void public_key_database::insert(public_key const& key) {
	octet_vector o = serialisation::asn_der_serialise(key);
	auto q = db_->prepare("INSERT OR REPLACE INTO public_keys VALUES(:i,:o);");
	q.bind(":i", key.id().in_hex());
	q.bind(":o", o);
	q.execute();
}

std::optional<public_key> public_key_database::find(public_key_id const& id) const {
	auto q = db_->prepare("SELECT data FROM public_keys WHERE p_key_id = :i LIMIT 1");
	q.bind(":i", id.in_hex());
	auto res = q.execute();
	std::optional<public_key> v;
	if(res) {
		std::optional<octet_vector> const o = res.value<octet_vector>(0);
		if(o) {
			v = serialisation::asn_der_deserialise<public_key>(*o);
		}
	}
	return v;
}

void public_key_database::remove(public_key_id const& id) {
	auto q = db_->prepare("DELETE FROM public_keys WHERE p_key_id = :i");
	q.bind(":i", id.in_hex());
	q.execute();
}

}
