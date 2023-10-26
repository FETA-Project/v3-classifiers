/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec table
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <unirec/unirec.h>

struct UnirecTable {
	UnirecTable() { update(); }

	// clang-format off
	ur_field_id_t SRC_IP;
	ur_field_id_t DST_IP;
	ur_field_id_t TOR_DETECTED;
	ur_field_id_t TOR_DIRECTION;
	// clang-format on

	void update()
	{
		SRC_IP = ur_get_id_by_name("SRC_IP");
		DST_IP = ur_get_id_by_name("DST_IP");
		TOR_DETECTED = ur_get_id_by_name("TOR_DETECTED");
		TOR_DIRECTION = ur_get_id_by_name("TOR_DIRECTION");
	}
};
