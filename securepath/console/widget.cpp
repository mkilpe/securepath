// SPDX-License-Identifier: MIT

#include "widget.hpp"

namespace securepath::console {

widget::widget(rect g)
: geo_(g)
{}

rect widget::geometry() const {
	return geo_;
}

}
