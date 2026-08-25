// SPDX-License-Identifier: MIT

#pragma once

#if defined(WIN32) or defined(USE_PDCURSES)
#	include "curses.h"
#	if !defined(PDC_WIDE)
#		error pdcurses need to have wide character support
#	endif
#else
#	include <ncursesw/ncurses.h>
#endif
