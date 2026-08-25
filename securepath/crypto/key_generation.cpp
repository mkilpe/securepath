// SPDX-License-Identifier: MIT

#include "key_generation.hpp"

#include "detail/hybrid_kem.hpp"
#include "detail/private_key_impl.hpp"
#include "detail/rng.hpp"
#include "detail/suite_parameters.hpp"

#include <botan/ml_dsa.h>

namespace securepath::crypto {

private_key generate_private_key(suite s) {
	auto const& p = detail::parameters(s);
	Botan::ML_DSA_PrivateKey sig(detail::rng(), Botan::ML_DSA_Mode(p.sig_mode));
	return private_key(std::make_shared<private_key_impl>(s, sig.raw_private_key_bits(), detail::generate_kem_private_key(s)));
}

}
