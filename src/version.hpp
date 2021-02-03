// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

// defines are for Windows resource compiler
#define infinium_VERSION_WINDOWS_COMMA 3, 19, 4, 18
#define infinium_VERSION_STRING "v3.0.0 (New Way)"

#ifndef RC_INVOKED  // Windows resource compiler

namespace cn {
inline const char *app_version() { return infinium_VERSION_STRING; }
}  // namespace cn

#endif
