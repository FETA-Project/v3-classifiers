/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief WIF Template
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

namespace TunDer {

// clang-format off
enum WIF_ID : unsigned int {
	SRC_IP,
	DST_IP,
	SRC_PORT,
	DST_PORT,
	TIME_LAST,
	OVPN_CONF_LEVEL,
	WG_CONF_LEVEL,
	SSA_CONF_LEVEL,
	TOR_DETECTED,
	SIZE
};
// clang-format on

} // namespace TunDer
