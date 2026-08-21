// SPDX-License-Identifier: MIT

#pragma once

#include <type_traits>

namespace securepath::serialisation {
	
	template<typename T, typename Ser>
	struct has_serialise {
		using type = typename std::decay<T>::type;

		template<typename Obj>
		static auto check(Obj*) -> decltype(std::declval<Obj&>().serialise(std::declval<Ser&>()));
		static std::false_type check(...);

		constexpr static bool value = !std::is_same<decltype(check((type*)0)), std::false_type>::value;
	};

	template<typename T, typename Ser>
	using serialise_enabler = typename std::enable_if<has_serialise<T, Ser>::value>::type;

	template<typename T, typename Ser>
	using serialise_disabler = typename std::enable_if<!has_serialise<T, Ser>::value>::type;

}

