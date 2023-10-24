/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec templates
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace TorDer {

const std::string UNIREC_IFC_INPUT_TEMPLATE
	= "ipaddr SRC_IP,"
	  "ipaddr DST_IP";

const std::string UNIREC_IFC_OUTPUT_TEMPLATE
	= "uint8 TOR_DETECTED,"
	  "int8 TOR_DIRECTION";

} // namespace TorDer
