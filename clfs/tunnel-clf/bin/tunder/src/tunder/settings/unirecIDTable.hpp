/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec ID Table
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <unirec/unirec.h>

struct UnirecIDTable {
	UnirecIDTable() { update(); }

	// clang-format off
	ur_field_id_t SRC_IP;
	ur_field_id_t DST_IP;

	ur_field_id_t SRC_PORT;
	ur_field_id_t DST_PORT;

	ur_field_id_t TOR_DETECTED;

	ur_field_id_t TIME_LAST;

	ur_field_id_t OVPN_CONF_LEVEL;
	ur_field_id_t WG_CONF_LEVEL;
	ur_field_id_t SSA_CONF_LEVEL;

	ur_field_id_t RULE;
	ur_field_id_t DETECT_TIME;

	ur_field_id_t RESULT_PORT_OVPN;
	ur_field_id_t RESULT_PORT_WG;
	ur_field_id_t RESULT_CONF_LEVEL_OVPN;
	ur_field_id_t RESULT_CONF_LEVEL_WG;
	ur_field_id_t RESULT_CONF_LEVEL_SSA;
	ur_field_id_t RESULT_TOR;
	ur_field_id_t RESULT_BLOCKLIST;

	ur_field_id_t EXPLANATION_PORT_OVPN;
	ur_field_id_t EXPLANATION_PORT_WG;
	ur_field_id_t EXPLANATION_CONF_LEVEL_OVPN;
	ur_field_id_t EXPLANATION_CONF_LEVEL_WG;
	ur_field_id_t EXPLANATION_CONF_LEVEL_SSA;
	ur_field_id_t EXPLANATION_TOR;
	ur_field_id_t EXPLANATION_BLOCKLIST;
	// clang-format on

	void update()
	{
		SRC_IP = ur_get_id_by_name("SRC_IP");
		DST_IP = ur_get_id_by_name("DST_IP");
		SRC_PORT = ur_get_id_by_name("SRC_PORT");
		DST_PORT = ur_get_id_by_name("DST_PORT");
		TOR_DETECTED = ur_get_id_by_name("TOR_DETECTED");
		TIME_LAST = ur_get_id_by_name("TIME_LAST");
		OVPN_CONF_LEVEL = ur_get_id_by_name("OVPN_CONF_LEVEL");
		WG_CONF_LEVEL = ur_get_id_by_name("WG_CONF_LEVEL");
		SSA_CONF_LEVEL = ur_get_id_by_name("SSA_CONF_LEVEL");
		RULE = ur_get_id_by_name("RULE");
		DETECT_TIME = ur_get_id_by_name("DETECT_TIME");
		RESULT_PORT_OVPN = ur_get_id_by_name("RESULT_PORT_OVPN");
		RESULT_PORT_WG = ur_get_id_by_name("RESULT_PORT_WG");
		RESULT_CONF_LEVEL_OVPN = ur_get_id_by_name("RESULT_CONF_LEVEL_OVPN");
		RESULT_CONF_LEVEL_WG = ur_get_id_by_name("RESULT_CONF_LEVEL_WG");
		RESULT_CONF_LEVEL_SSA = ur_get_id_by_name("RESULT_CONF_LEVEL_SSA");
		RESULT_TOR = ur_get_id_by_name("RESULT_TOR");
		RESULT_BLOCKLIST = ur_get_id_by_name("RESULT_BLOCKLIST");
		EXPLANATION_PORT_OVPN = ur_get_id_by_name("EXPLANATION_PORT_OVPN");
		EXPLANATION_PORT_WG = ur_get_id_by_name("EXPLANATION_PORT_WG");
		EXPLANATION_CONF_LEVEL_OVPN = ur_get_id_by_name("EXPLANATION_CONF_LEVEL_OVPN");
		EXPLANATION_CONF_LEVEL_WG = ur_get_id_by_name("EXPLANATION_CONF_LEVEL_WG");
		EXPLANATION_CONF_LEVEL_SSA = ur_get_id_by_name("EXPLANATION_CONF_LEVEL_SSA");
		EXPLANATION_TOR = ur_get_id_by_name("EXPLANATION_TOR");
		EXPLANATION_BLOCKLIST = ur_get_id_by_name("EXPLANATION_BLOCKLIST");
	}
};
