// SPDX-License-Identifier: MIT

#pragma once

#include "certificate_access.hpp"

#include <securepath/database/connection.hpp>

#include <optional>
#include <string>
#include <vector>

namespace securepath::crypto {

/// Certificates in a sqlite table (certificates: id hex, DER BLOB, identifier, revoked flag)
class certificate_database : public certificate_access {
public:
	certificate_database(database::connection_ptr c);

	/// throws error(errc::invalid_operation) when trying to replace a revoked certificate
	void insert(certificate const&) override;
	void remove(certificate_id const&) override;
	std::optional<certificate> find(certificate_id const&) const override;
	std::vector<certificate> search_identifier(std::string const& identifier) const override;

private:
	bool is_revoked(certificate_id const&) const;
	static std::optional<std::string> extract_identifier(certificate const&);

private:
	database::connection_ptr db_;
};

}
