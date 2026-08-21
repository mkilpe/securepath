// SPDX-License-Identifier: MIT

#pragma once

#include "has_serialise.hpp"
#include "helpers.hpp"
#include "tag.hpp"

#include <securepath/serialisation/codec/encoder.hpp>

#include <memory>

namespace securepath::serialisation {

class serialiser {
public:
	serialiser(std::unique_ptr<encoder> enc)
	: own_(std::move(enc))
	, e_(&*own_)
	{}

	serialiser(encoder& enc)
	: e_(&enc)
	{}

	template<typename T, typename = std::enable_if_t<!std::is_integral<T>::value>>
	void handle(T const& v) {
		e_->encode(v, use_current_tag());
	}

	void handle(bool v) {
		e_->encode(v, use_current_tag());
	}

	template<typename Integer, typename = std::enable_if_t<std::is_integral<Integer>::value>>
	void handle(Integer v, int=0) {
		using promote_type = typename std::conditional<std::is_unsigned<Integer>::value, std::uint64_t, std::int64_t>::type;
		e_->encode(promote_type{v}, use_current_tag(), sizeof(v));
	}

	void handle(integer const& v) {
		e_->encode(v, use_current_tag());
	}

	void handle(float v) {
		e_->encode(double{v}, use_current_tag());
	}

	template<typename T>
	void handle_tag(object_with_tag<T> const& t) {
		if(t.type == tag_type::implicit_tag) {
			current_tag_ = t.tag;
			*this & t.obj;
		} else {
			e_->start_explicit_tag(t.tag);
			*this & t.obj;
			e_->end_explicit_tag();
		}
	}

	template<typename T>
	void handle(object_with_tag<T> const& t) {
		handle_tag(t);
	}

	template<typename T>
	void handle(object_with_tag<std::optional<T>> const& t) {
		if(t.obj) {
			handle_tag(t);
		}
	}

	template<typename T>
	void handle(std::optional<T> const& v) {
		if(v) {
			*this & *v;
		}
	}

	void handle(trailing_data const& d) {
		//should we just drop pending tags?
		e_->encode(d);
	}

	void start_sequence() {
		e_->start_sequence(use_current_tag());
	}

	void start_sequence(tag_info const& tag) {
		e_->start_sequence(use_current_tag().value_or(tag));
	}

	void end_sequence() {
		e_->end_sequence();
	}

private:
	std::optional<tag_info> use_current_tag() {
		auto r = current_tag_;
		current_tag_ = std::nullopt;
		return r;
	}
private:
	std::unique_ptr<encoder> own_;
	encoder* e_;
	std::optional<tag_info> current_tag_;
};

// allow to serialise c-strings but not deserialise; lives here rather than in
// helpers.hpp because it instantiates serialise() against the complete serialiser
inline
serialiser& operator&(serialiser& s, char const* v) {
	return serialise(s, std::string(v));
}

template<typename Encoder, typename... Args>
serialiser make_serialiser(Args&&... args) {
	return serialiser(std::make_unique<Encoder>(std::forward<Args>(args)...));
}

}

