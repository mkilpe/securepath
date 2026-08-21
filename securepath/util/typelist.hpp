// SPDX-License-Identifier: MIT

#pragma once

#include <type_traits>

namespace securepath {

template<typename... Types>
struct typelist_iterator;

template<typename Type, typename... Types>
struct typelist_iterator<Type, Types...> {
	typedef Type value_type;
	typedef typelist_iterator<Types...> next;
};

template<typename... Types>
struct typelist {
	static std::size_t const size = sizeof...(Types);
	typedef typelist_iterator<Types...> begin;
};

template<typename Typelist>
struct begin {
	using type = typename Typelist::begin;
};

template<typename Iterator>
struct next {
	using type = typename Iterator::next;
};

template<typename Typelist>
struct end {
	using type = typelist_iterator<>;
};

template<typename Iter, typename End, std::size_t Pos>
struct get_element {
	using type = typename get_element<typename next<Iter>::type, End, Pos-1>::type;
};

template<typename Iter, typename End>
struct get_element<Iter, End, 0> {
	using type = typename Iter::value_type;	
};

template<typename End, std::size_t Pos>
struct get_element<End, End, Pos> {
};

template<typename End>
struct get_element<End, End, 0> {
};

template<typename Typelist, std::size_t Pos>
struct nth_element {
	using type = typename get_element<typename begin<Typelist>::type, typename end<Typelist>::type, Pos>::type;
};

}

