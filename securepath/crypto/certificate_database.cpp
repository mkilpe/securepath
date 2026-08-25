// SPDX-License-Identifier: MIT

#include "certificate_database.hpp"

#include "error.hpp"
#include "identifier_certificate.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto {

certificate_database::certificate_database(database::connection_ptr c)
: db_(std::move(c))
{
	if(!db_->has_table("certificates")) {
		db_->prepare("CREATE TABLE certificates(cert_id TEXT PRIMARY KEY, data BLOB, identifier TEXT, revoked INTEGER);").execute();
	}
}

bool certificate_database::is_revoked(certificate_id const& id) const {
	auto q = db_->prepare("SELECT count(*) FROM certificates WHERE cert_id = :c AND revoked = 1");
	q.bind(":c", id.in_hex());
	auto res = q.execute();
	return res && res.value<std::int64_t>(0).value_or(0) != 0;
}

void certificate_database::insert(certificate const& cert) {
	if(is_revoked(cert.id())) {
		LOG_WARN("trying to replace revoked certificate ({})", cert.id());
		throw error(errc::invalid_operation);
	}
	std::optional<std::string> identifier = extract_identifier(cert);
	octet_vector o = serialisation::asn_der_serialise(cert);
	auto q = db_->prepare("INSERT OR REPLACE INTO certificates VALUES(:c,:d,:i,:r)");
	q.bind(":c", cert.id().in_hex());
	q.bind(":d", o);
	if(identifier) {
		q.bind(":i", *identifier);
	}
	q.bind(":r", std::int64_t(cert.revocation() ? 1 : 0));
	q.execute();
}

void certificate_database::remove(certificate_id const& id) {
	auto q = db_->prepare("DELETE FROM certificates WHERE cert_id = :i");
	q.bind(":i", id.in_hex());
	q.execute();
}

std::optional<std::string> certificate_database::extract_identifier(certificate const& cert) {
	std::optional<std::string> res;
	if(cert.type() == int(identifier_certificate_data::id)) {
		try {
			res = cert.extract<identifier_certificate_data>().identifier();
		} catch(std::exception const& e) {
			LOG_WARN("extract certificate {} exception: {}", cert.id(), e.what());
		}
	}
	return res;
}

std::optional<certificate> certificate_database::find(certificate_id const& cert_id) const {
	std::optional<certificate> cert_opt;
	auto q = db_->prepare("SELECT data FROM certificates WHERE cert_id = :c LIMIT 1");
	q.bind(":c", cert_id.in_hex());
	auto res = q.execute();
	if(res) {
		std::optional<octet_vector> const o = res.value<octet_vector>(0);
		if(o) {
			cert_opt = serialisation::asn_der_deserialise<certificate>(*o);
		}
	}
	return cert_opt;
}

std::vector<certificate> certificate_database::search_identifier(std::string const& identifier) const {
	std::vector<certificate> vec;
	auto q = db_->prepare("SELECT data FROM certificates WHERE identifier = :i");
	q.bind(":i", identifier);
	auto res = q.execute();
	if(res) {
		do {
			std::optional<octet_vector> const o = res.value<octet_vector>(0);
			if(o) {
				vec.push_back(serialisation::asn_der_deserialise<certificate>(*o));
			}
		} while(res.next());
	}
	return vec;
}

}
