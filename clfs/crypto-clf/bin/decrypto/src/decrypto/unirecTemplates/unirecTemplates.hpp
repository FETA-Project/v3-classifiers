/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec templates interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>

namespace DeCrypto {

namespace Templates {

const std::string INPUT_IFC_TEMPLATE
	= "ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT,uint8 PROTOCOL,uint64 "
	  "BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,time TIME_FIRST,time "
	  "TIME_LAST,uint8 TCP_FLAGS,uint8 TCP_FLAGS_REV,bytes IDP_CONTENT,bytes "
	  "IDP_CONTENT_REV,string TLS_SNI,int8* PPI_PKT_DIRECTIONS,time* PPI_PKT_TIMES,uint16* "
	  "PPI_PKT_LENGTHS,uint8* PPI_PKT_FLAGS";
const std::string INPUT_IFC_TEMPLATE_DEBUG = INPUT_IFC_TEMPLATE + ",string LABEL";
const std::string OUTPUT_IFC_TEMPLATE
	= "ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT,uint8 PROTOCOL,uint64 "
	  "BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,time TIME_FIRST,time "
	  "TIME_LAST,string TLS_SNI,uint8 PREDICTION,string EXPLANATION,time DETECT_TIME";
const std::string OUTPUT_IFC_TEMPLATE_DEBUG = OUTPUT_IFC_TEMPLATE + ",string LABEL";

std::string getInputTemplate(bool debug);

std::string getOutputTemplate(bool debug);

} // namespace Templates

} // namespace DeCrypto
