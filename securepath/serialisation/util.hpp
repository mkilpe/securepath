// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/deserialiser.hpp>
#include <securepath/serialisation/serialiser.hpp>
#include <securepath/serialisation/codec/asn_der/asn_der_decoder.hpp>
#include <securepath/serialisation/codec/asn_der/asn_der_encoder.hpp>
#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/octet_vector_stream.hpp>
#include <securepath/util/error.hpp>

namespace securepath::serialisation {

/// Easy function to serialise single object with given stream using asn.1 der
template<typename Stream, typename T>
auto asn_der_serialise(Stream& out, T&& t) -> decltype(out.write(std::declval<char const*>(), 0), void()) {
	serialisation::asn_der_encoder<Stream> enc(out);
	serialisation::serialiser ser(enc);
	ser & t;
}

/// Easy function to deserialise single object from stream using asn.1 der
template<typename T, typename Stream>
auto asn_der_deserialise(Stream& in) -> decltype(in.read(std::declval<char*>(), 0), T{}) {
#ifndef NDEBUG
	try {
#endif

	serialisation::asn_der_decoder<Stream> dec(in);
	serialisation::deserialiser deser(dec);
	T t{};
	deser & t;
	return t;

#ifndef NDEBUG
	} catch(serialisation_error const&) {
		LOG_WARN("failed to deserialise type '{}'", typeid(T).name());
		throw;
	}
#endif
}


/// Easy function to serialise single object with asn.1 der
template<typename T>
octet_vector asn_der_serialise(T&& t) {
	octet_vector v;
	octet_vector_ostream ss(v);
	asn_der_serialise(ss, std::forward<T>(t));
	return v;
}

/// Easy function to deserialise single object with asn.1 der
template<typename T>
T asn_der_deserialise(octet_span d) {
	octet_span_istream ss(d);
	return asn_der_deserialise<T>(ss);
}

/// Easy function to deserialise single object with asn.1 der
template<typename T>
T asn_der_deserialise(octet_vector const& v) {
	return asn_der_deserialise<T>(octet_span(v));
}

/**
 * Easy function to serialise single object as asn.1 choice
 * ChoiceTypeList is of form typelist<type_tag<test1, 1>, type_tag<test2, 2>>.
 * If the serialised type is not in the list, serialisation_error is thrown
 */
template<typename ChoiceTypeList, typename T>
octet_vector asn_der_serialise_choice(T&& t) {
	octet_vector vec;
	octet_vector_ostream ss(vec);
	asn_der_encoder<octet_vector_ostream> enc(ss);
	serialiser ser(enc);
	serialisation::choice<ChoiceTypeList>::serialise(ser, std::forward<T>(t));
	return vec;
}

/**
 * Easy function to deserialise asn.1 choice.
 * ChoiceTypeList is of form typelist<type_tag<test1, 1>, type_tag<test2, 2>>, and contains
 * the types in choice. The visitor is called with the type active in the choice.
 * VisitReturn is return type for the visitor and will be passed to the user. Must be the same
 * type for all visited types.
 */
template<typename ChoiceTypeList, typename VisitReturn, typename Visitor>
VisitReturn asn_der_deserialise_choice(octet_span const& span, Visitor&& v) {
	octet_span_istream ss(span);
	asn_der_decoder<octet_span_istream> dec(ss);
	deserialiser deser(dec);
	return serialisation::choice<ChoiceTypeList, VisitReturn>::deserialise(deser, std::forward<Visitor>(v));
}

/// Easy function to deserialise asn.1 choice without visitor return type.
template<typename ChoiceTypeList, typename Visitor>
void asn_der_deserialise_choice(octet_span const& span, Visitor&& v) {
	asn_der_deserialise_choice<ChoiceTypeList, void, Visitor>(span, std::forward<Visitor>(v));
}

/**
 * Helper for network handling where incoming packets need to be deserialised
 * Checks if there is next packet to be deserialised
 */
class packet_deserialiser_base {
public:
	packet_deserialiser_base() = default;
	packet_deserialiser_base(std::size_t max)
	: buf_max_size_(max)
	{}

	/// check if there are enough octets to deserialise next packet and call the callback for the deserialiser and data
	template<typename Callback>
	void do_check(octet_span data, Callback callback) {
		if(buf_.size() + data.size() > buf_max_size_) {
			throw make_error(errc::constraint_violation, "max buffer size reached");
		}

		std::uint64_t length = 0, pos = 0;
		auto deser_func = [&] (octet_span const& s) {
			serialisation::octet_span_istream ss(s);
			serialisation::asn_der_decoder<serialisation::octet_span_istream> input(ss);
			serialisation::deserialiser deser(input);
			if((length = deser.has_next())) {
				callback(deser, octet_span(s.begin(), s.begin()+length));
				pos += length;
			}
			return length;
		};
		if(buf_.empty()) {
			while( deser_func(octet_span(data.begin()+pos, data.end())) ) {}
			buf_.insert(buf_.end(), data.begin()+pos, data.end());
		} else {
			buf_.insert(buf_.end(), data.begin(), data.end());
			while( deser_func(octet_span(buf_.data()+pos, buf_.size()-pos)) ) {}
			buf_.erase(buf_.begin(), buf_.begin()+pos);
		}
	}

	void clear() {
		buf_.clear();
	}

private:
	// default cap to 1M bytes
	std::size_t const buf_max_size_{1024*1024};
	octet_vector buf_;
};

/**
 * Helper for network handling where incoming packets need to be deserialised
 * Deserialises asn.1 choice
 */
template<typename ChoiceTypeList>
class packet_deserialiser : public packet_deserialiser_base {
public:
	template<typename Visitor>
	void handle(octet_span data, Visitor visitor) {
		do_check(data, [visitor](auto& deser, octet_span)
		{
			serialisation::choice<ChoiceTypeList, void>::deserialise(deser, visitor);
		});
	}
};


}

