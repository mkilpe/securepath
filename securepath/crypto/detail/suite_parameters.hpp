// SPDX-License-Identifier: MIT

#pragma once

#include "../suite.hpp"

#include <botan/dilithium.h>
#include <botan/kyber.h>

#include <cstddef>
#include <string_view>

namespace securepath::crypto::detail {

/// concrete algorithms and sizes behind a suite id
struct suite_parameters {
	suite id{};
	std::string_view name;
	Botan::DilithiumMode::Mode sig_mode{};
	Botan::KyberMode::Mode kem_mode{};
	bool x448{};                   ///< classical KEM half: X448 when true, X25519 otherwise
	std::size_t x_key_size{};      ///< X25519/X448 public key, private key and ciphertext size
	std::size_t sig_public_size{};
	std::size_t sig_seed_size{32};
	std::size_t signature_size{};
	std::size_t kem_public_size{};
	std::size_t kem_seed_size{64};
	std::size_t kem_ciphertext_size{};
};

/// throws unknown_suite
suite_parameters const& parameters(suite);

}
