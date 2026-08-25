// SPDX-License-Identifier: MIT

#include "hybrid_kem.hpp"
#include "rng.hpp"
#include "suite_parameters.hpp"
#include "../types.hpp"

#include <botan/exceptn.h>
#include <botan/kdf.h>
#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <botan/x25519.h>
#include <botan/x448.h>

#include <memory>
#include <string>

namespace securepath::crypto::detail {
namespace {

std::unique_ptr<Botan::PK_Key_Agreement_Key> make_x_private(suite_parameters const& p, std::span<std::uint8_t const> sk) {
	std::unique_ptr<Botan::PK_Key_Agreement_Key> ret;
	if(p.x448) {
		ret = std::make_unique<Botan::X448_PrivateKey>(sk);
	} else {
		ret = std::make_unique<Botan::X25519_PrivateKey>(sk);
	}
	return ret;
}

std::unique_ptr<Botan::PK_Key_Agreement_Key> make_x_ephemeral(suite_parameters const& p) {
	std::unique_ptr<Botan::PK_Key_Agreement_Key> ret;
	if(p.x448) {
		ret = std::make_unique<Botan::X448_PrivateKey>(rng());
	} else {
		ret = std::make_unique<Botan::X25519_PrivateKey>(rng());
	}
	return ret;
}

Botan::secure_vector<std::uint8_t> x_agree(suite_parameters const& p, Botan::PK_Key_Agreement_Key const& sk, octet_span peer) {
	Botan::PK_Key_Agreement ka(sk, rng(), "Raw");
	return ka.derive_key(p.x_key_size, peer.data(), peer.size()).bits_of();
}

void check_public_sizes(suite_parameters const& p, kem_public_key const& pk) {
	if(pk.x_pk.size() != p.x_key_size || pk.pq_pk.size() != p.kem_public_size) {
		throw invalid_key("kem public key does not match the suite");
	}
}

void check_private_sizes(suite_parameters const& p, kem_private_key const& sk) {
	if(sk.x_sk.size() != p.x_key_size || sk.pq_seed.size() != p.kem_seed_size) {
		throw invalid_key("kem private key does not match the suite");
	}
}

template<typename T>
octet_vector to_octets(T const& v) {
	return octet_vector(v.begin(), v.end());
}

}

Botan::secure_vector<std::uint8_t> combine_shared_secrets(suite s, octet_span ss_pq, octet_span ss_x, octet_span ct_x, octet_span pk_x) {
	Botan::secure_vector<std::uint8_t> ikm;
	ikm.insert(ikm.end(), ss_pq.begin(), ss_pq.end());
	ikm.insert(ikm.end(), ss_x.begin(), ss_x.end());
	ikm.insert(ikm.end(), ct_x.begin(), ct_x.end());
	ikm.insert(ikm.end(), pk_x.begin(), pk_x.end());
	std::string const info = "securepath-kem-v1/" + std::string(to_string(s));
	auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-3(256))");
	return kdf->derive_key(kem_key_size, ikm, std::string_view{}, info);
}

kem_private_key generate_kem_private_key(suite s) {
	auto const& p = parameters(s);
	kem_private_key ret;
	ret.id = s;
	ret.x_sk = make_x_ephemeral(p)->raw_private_key_bits();
	ret.pq_seed = Botan::ML_KEM_PrivateKey(rng(), Botan::ML_KEM_Mode(p.kem_mode)).raw_private_key_bits();
	return ret;
}

kem_public_key kem_public_part(kem_private_key const& sk) {
	auto const& p = parameters(sk.id);
	check_private_sizes(p, sk);
	kem_public_key ret;
	ret.id = sk.id;
	ret.x_pk = make_x_private(p, sk.x_sk)->raw_public_key_bits();
	ret.pq_pk = Botan::ML_KEM_PrivateKey(sk.pq_seed, Botan::ML_KEM_Mode(p.kem_mode)).public_key_bits();
	return ret;
}

kem_encapsulation kem_encapsulate(kem_public_key const& pk) {
	auto const& p = parameters(pk.id);
	check_public_sizes(p, pk);
	try {
		auto eph = make_x_ephemeral(p);
		auto ss_x = x_agree(p, *eph, pk.x_pk);

		Botan::ML_KEM_PublicKey pq_pk(pk.pq_pk, Botan::ML_KEM_Mode(p.kem_mode));
		Botan::PK_KEM_Encryptor enc(pq_pk, "Raw");
		auto pq = enc.encrypt(rng(), kem_key_size);

		kem_encapsulation ret;
		ret.ct_x = eph->raw_public_key_bits();
		ret.ct_pq = to_octets(pq.encapsulated_shared_key());
		ret.key = combine_shared_secrets(pk.id, pq.shared_key(), ss_x, ret.ct_x, pk.x_pk);
		return ret;
	} catch(Botan::Exception const& e) {
		throw invalid_key(std::string("kem encapsulation failed: ") + e.what());
	}
}

Botan::secure_vector<std::uint8_t> kem_decapsulate(kem_private_key const& sk, octet_span ct_x, octet_span ct_pq) {
	auto const& p = parameters(sk.id);
	check_private_sizes(p, sk);
	if(ct_x.size() != p.x_key_size || ct_pq.size() != p.kem_ciphertext_size) {
		throw bad_ciphertext("kem ciphertext does not match the suite");
	}
	try {
		auto x_sk = make_x_private(p, sk.x_sk);
		auto ss_x = x_agree(p, *x_sk, ct_x);

		Botan::ML_KEM_PrivateKey pq_sk(sk.pq_seed, Botan::ML_KEM_Mode(p.kem_mode));
		Botan::PK_KEM_Decryptor dec(pq_sk, rng(), "Raw");
		auto ss_pq = dec.decrypt(ct_pq, kem_key_size);

		return combine_shared_secrets(sk.id, ss_pq, ss_x, ct_x, x_sk->raw_public_key_bits());
	} catch(Botan::Exception const& e) {
		throw bad_ciphertext(std::string("kem decapsulation failed: ") + e.what());
	}
}

}
