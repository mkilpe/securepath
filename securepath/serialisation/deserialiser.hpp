// SPDX-License-Identifier: MIT

#pragma once

#include "has_serialise.hpp"
#include "helpers.hpp"
#include "tag.hpp"

#include <securepath/serialisation/codec/decoder.hpp>

#include <memory>

namespace securepath::serialisation {

class deserialiser {
public:
	deserialiser(std::unique_ptr<decoder> dec)
	: own_(std::move(dec))
	, d_(&*own_)
	{}

	deserialiser(decoder& dec)
	: d_(&dec)
	{}

	template<typename T, typename = std::enable_if_t<!std::is_integral<T>::value>>
	void handle(T& v) {
		d_->decode(v, use_current_tag());
	}

	void handle(bool& v) {
		d_->decode(v, use_current_tag());
	}

	template<typename Integer, typename = std::enable_if_t<std::is_integral<Integer>::value>>
	void handle(Integer& v, int=0) {
		using promote_type = typename std::conditional<std::is_unsigned<Integer>::value, std::uint64_t, std::int64_t>::type;
		promote_type temp{};
		d_->decode(temp, use_current_tag(), sizeof(v));
		v = static_cast<Integer>(temp);
	}

	void handle(integer& v) {
		d_->decode(v, use_current_tag());
	}

	void handle(float& v) {
		double temp{};
		d_->decode(temp, use_current_tag());
		v = static_cast<float>(temp);
	}

	template<typename T>
	void handle_tag(object_with_tag<T>& t) {
		if(t.type == tag_type::implicit_tag) {
			current_tag_ = t.tag;
			*this & t.obj;
		} else {
			d_->start_explicit_tag(t.tag);
			*this & t.obj;
			d_->end_explicit_tag();
		}
	}

	template<typename T>
	void handle(object_with_tag<T>&& t) {
		handle_tag(t);
	}

	template<typename T>
	void handle(object_with_tag<std::optional<T>>&& t) {
		if(t.type == tag_type::implicit_tag) {
			handle_tag(t);
		} else {
			handle(t.obj, t.tag);
		}
	}

	template<typename T>
	void handle(std::optional<T>& v, std::optional<tag_info> etag = std::nullopt) {
		try {
			peek_guard g(*d_);
			if(etag) {
				d_->start_explicit_tag(*etag);
			}
			T temp{};
			*this & temp;
			v = std::move(temp);
			if(etag) {
				d_->end_explicit_tag();
			}
		} catch(element_not_present const&) {
			// the field is genuinely absent (old file / different tag); any
			// other decode failure is corrupt data and must propagate
			v = std::nullopt;
		}
	}

	void handle(trailing_data& d) {
		d_->decode(d);
	}

	void start_sequence() {
		d_->start_sequence(use_current_tag());
	}

	void start_sequence(tag_info const& tag) {
		d_->start_sequence(use_current_tag().value_or(tag));
	}

	void end_sequence() {
		try {
			d_->end_sequence();
		} catch(...) {
			ex_ = std::current_exception();
		}
	}

	tag_info next_tag() {
		return d_->next_tag();
	}

	bool is_end_of_sequence() const {
		return d_->is_end_of_sequence();
	}

	uint64_t has_next() const {
		return d_->has_next();
	}

	uint64_t position() const {
		return d_->position();
	}

	std::exception_ptr move_exception() {
		std::exception_ptr p{};
		std::swap(ex_, p);
		return p;
	}
private:
	std::optional<tag_info> use_current_tag() {
		auto r = current_tag_;
		current_tag_ = std::nullopt;
		return r;
	}
private:
	std::unique_ptr<decoder> own_;
	decoder* d_;
	std::optional<tag_info> current_tag_;
	std::exception_ptr ex_;
};

template<typename Decoder, typename... Args>
deserialiser make_deserialiser(Args&&... args) {
	return deserialiser(std::make_unique<Decoder>(std::forward<Args>(args)...));
}

}

