// SPDX-License-Identifier: MIT

#pragma once

#include <tuple>
#include <type_traits>

namespace securepath {

template<typename ToRemove, typename... T>
auto make_tuple_without_impl(std::tuple<T...>&& tuple) {
	return tuple;
}

template<typename ToRemove, typename... T, typename Arg, typename... Args>
auto make_tuple_without_impl(std::tuple<T...>&& tuple, Arg&& arg, Args&&... args) {
	using type = std::decay_t<Arg>;
	if constexpr(std::is_same_v<type, ToRemove>) {
		return make_tuple_without_impl<ToRemove>(std::move(tuple), std::forward<Args>(args)...);
	} else {
		return make_tuple_without_impl<ToRemove>(std::tuple_cat(std::move(tuple), std::make_tuple(std::forward<Arg>(arg))), std::forward<Args>(args)...);
	}
}

template<typename ToRemove, typename... Args>
auto make_tuple_without(Args&&... args) {
	return make_tuple_without_impl<ToRemove>(std::tuple<>{}, std::forward<Args>(args)...);
}

}

