/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief WIF ID table implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/translationTable/wifIDTable.hpp"

using namespace WIF;

namespace DeCrypto {

WifIDTable::WifIDTable()
{
	init();
}

void WifIDTable::init()
{
	FeatureID nextAvailableId = 0;
	SRC_IP = nextAvailableId++;
	DST_IP = nextAvailableId++;
	SRC_PORT = nextAvailableId++;
	DST_PORT = nextAvailableId++;
	PROTOCOL = nextAvailableId++;
	BYTES = nextAvailableId++;
	BYTES_REV = nextAvailableId++;
	PACKETS = nextAvailableId++;
	PACKETS_REV = nextAvailableId++;
	TIME_FIRST = nextAvailableId++;
	TIME_LAST = nextAvailableId++;
	TCP_FLAGS = nextAvailableId++;
	TCP_FLAGS_REV = nextAvailableId++;
	IDP_CONTENT = nextAvailableId++;
	IDP_CONTENT_REV = nextAvailableId++;
	TLS_SNI = nextAvailableId++;
	LABEL = nextAvailableId++;
	F_SENT = nextAvailableId++;
	F_RECV = nextAvailableId++;
	F_AVG_PKT_INTERVAL = nextAvailableId++;
	F_OVERALL_DURATION = nextAvailableId++;
	F_AVG_PKT_SIZE = nextAvailableId++;
	F_PUSH_RATIO = nextAvailableId++;
	F_MIN_PKT_LEN = nextAvailableId++;
	F_DATA_SYMMETRY = nextAvailableId++;
	m_size = nextAvailableId;
}

} // namespace DeCrypto
