/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec ID table
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <unirec/unirec.h>

namespace DeCrypto {

class UnirecIDTable {
	using UnirecID = ur_field_id_t;

public:
	UnirecID SRC_IP;
	UnirecID DST_IP;
	UnirecID SRC_PORT;
	UnirecID DST_PORT;
	UnirecID PROTOCOL;
	UnirecID BYTES;
	UnirecID BYTES_REV;
	UnirecID PACKETS;
	UnirecID PACKETS_REV;
	UnirecID TCP_FLAGS;
	UnirecID TCP_FLAGS_REV;
	UnirecID TIME_FIRST;
	UnirecID TIME_LAST;
	UnirecID DETECT_TIME;
	UnirecID IDP_CONTENT;
	UnirecID IDP_CONTENT_REV;
	UnirecID TLS_SNI;
	UnirecID LABEL;
	UnirecID PPI_PKT_TIMES;
	UnirecID PPI_PKT_FLAGS;
	UnirecID PPI_PKT_LENGTHS;
	UnirecID PPI_PKT_DIRECTIONS;
	UnirecID PREDICTION;
	UnirecID EXPLANATION;
};

} // namespace DeCrypto
