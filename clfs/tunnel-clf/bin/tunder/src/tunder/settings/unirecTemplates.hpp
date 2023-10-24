/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec templates
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace TunDer {

const std::string UNIREC_IFC_INPUT_TEMPLATE
	= "ipaddr SRC_IP,"
	  "ipaddr DST_IP,"
	  "uint16 SRC_PORT,"
	  "uint16 DST_PORT,"
	  "time TIME_LAST,"
	  "uint8 OVPN_CONF_LEVEL,"
	  "uint8 WG_CONF_LEVEL,"
	  "uint8 SSA_CONF_LEVEL,"
	  "uint8 TOR_DETECTED";

const std::string UNIREC_IFC_OUTPUT_TEMPLATE
	= "ipaddr SRC_IP,"
	  "string RULE,"
	  "time DETECT_TIME,"
	  "uint8 RESULT_PORT_OVPN,"
	  "uint8 RESULT_PORT_WG,"
	  "uint8 RESULT_CONF_LEVEL_OVPN,"
	  "uint8 RESULT_CONF_LEVEL_WG,"
	  "uint8 RESULT_CONF_LEVEL_SSA,"
	  "uint8 RESULT_TOR,"
	  "uint8 RESULT_BLOCKLIST,"
	  "string EXPLANATION_PORT_OVPN,"
	  "string EXPLANATION_PORT_WG,"
	  "string EXPLANATION_CONF_LEVEL_OVPN,"
	  "string EXPLANATION_CONF_LEVEL_WG,"
	  "string EXPLANATION_CONF_LEVEL_SSA,"
	  "string EXPLANATION_TOR,"
	  "string EXPLANATION_BLOCKLIST";

} // namespace TunDer
