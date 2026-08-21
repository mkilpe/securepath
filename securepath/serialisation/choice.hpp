// SPDX-License-Identifier: MIT

#pragma once

#include "tag.hpp"
#include <securepath/util/typelist.hpp>
#include <securepath/log/log.hpp>

#include <type_traits>

namespace securepath::serialisation {

template<typename Type, uint64_t Tag>
struct type_tag {
	static uint64_t const tag = Tag;
	using type = Type;
};

template<typename Iterator, typename End, typename VisitReturn = void>
struct choice_impl {
	template<typename Ser, typename Visitor>
	static VisitReturn deserialise(Ser&& s, Visitor&& v) {
		tag_info tag = s.next_tag();
		return visit(tag, std::forward<Ser>(s), std::forward<Visitor>(v));
	}

	template<typename Ser, typename Visitor>
	static VisitReturn visit(tag_info tag, Ser&& s, Visitor&& v) {
		if(Iterator::value_type::tag == tag.tag) {
			using object_type = typename Iterator::value_type::type;
			if constexpr(std::is_convertible_v<std::invoke_result_t<Visitor, object_type>, VisitReturn>) {
				object_type object;
				s & implicit_tag(tag.tag, object);
				return v(object);
			} else {
				LOG_TRACE("invalid return type when visiting choice");
				throw serialisation_error("invalid return type when visiting choice");
			}
		} else {
			return choice_impl<typename next<Iterator>::type, End, VisitReturn>
				::visit(tag, std::forward<Ser>(s), std::forward<Visitor>(v));
		}
	}

	template<typename Type, typename Ser>
	static void serialise(Ser&& s, Type&& value) {
		if(std::is_same<typename std::decay<Type>::type, typename Iterator::value_type::type>::value) {
			s & implicit_tag(Iterator::value_type::tag, value);
		} else {
			choice_impl<typename next<Iterator>::type, End, VisitReturn>
				::template serialise<Type>(std::forward<Ser>(s), std::forward<Type>(value));
		}
	}
};

template<typename End, typename VisitReturn>
struct choice_impl<End, End, VisitReturn> {
	template<typename Ser, typename Visitor>
	static VisitReturn visit(tag_info t, Ser&&, Visitor&& v) {
		LOG_TRACE("no such tag with choice: {}", t.tag);
		throw serialisation_error("no such tag with choice");
	}

	template<typename Type, typename Ser>
	static void serialise(Ser&&, Type&& value) {
		LOG_TRACE("no such type with choice: {}", typeid(value).name());
		throw serialisation_error("no such type with choice");
	}
};

template<typename Typelist, typename VisitReturn = void>
struct choice {
	template<typename Type, typename Ser>
	static void serialise(Ser&& s, Type&& value) {
		choice_impl<
			typename begin<Typelist>::type,
			typename end<Typelist>::type,
			VisitReturn
			>::serialise(s, std::forward<Type>(value));
	}

	template<typename Ser, typename Visitor>
	static VisitReturn deserialise(Ser&& s, Visitor&& v) {
		return choice_impl<
			typename begin<Typelist>::type,
			typename end<Typelist>::type,
			VisitReturn
			>::deserialise(s, std::forward<Visitor>(v));
	}
};

}

