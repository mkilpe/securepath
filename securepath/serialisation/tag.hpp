// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

namespace securepath::serialisation {
	
	enum class tag_type { explicit_tag = 1, implicit_tag = 2 };

	template<typename Type>
	struct object_with_tag {
		tag_type type;
		tag_info tag;
		Type& obj;
	};

	template<typename Type>
	inline
	object_with_tag<Type> tag(tag_type tt, std::uint64_t t, Type& obj) {
		return {tt, tag_info{std::nullopt, t}, obj};
	}

	template<typename Type>
	inline
	object_with_tag<Type> implicit_tag(std::uint64_t t, Type& obj) {
		return tag(tag_type::implicit_tag, t, obj);
	}

	template<typename Type>
	inline
	object_with_tag<Type> explicit_tag(std::uint64_t t, Type& obj) {
		return tag(tag_type::explicit_tag, t, obj);
	}

}

