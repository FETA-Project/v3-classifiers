/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Translation table implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/translationTable/translationTable.hpp"

namespace DeCrypto {

TranslationTable::TranslationTable()
{
	update();
}

void TranslationTable::update()
{
	// Update field IDs when unirec template changes
	m_unirecIdTable.SRC_IP = ur_get_id_by_name("SRC_IP");
	m_unirecIdTable.DST_IP = ur_get_id_by_name("DST_IP");
	m_unirecIdTable.SRC_PORT = ur_get_id_by_name("SRC_PORT");
	m_unirecIdTable.DST_PORT = ur_get_id_by_name("DST_PORT");
	m_unirecIdTable.PROTOCOL = ur_get_id_by_name("PROTOCOL");
	m_unirecIdTable.BYTES = ur_get_id_by_name("BYTES");
	m_unirecIdTable.BYTES_REV = ur_get_id_by_name("BYTES_REV");
	m_unirecIdTable.PACKETS = ur_get_id_by_name("PACKETS");
	m_unirecIdTable.PACKETS_REV = ur_get_id_by_name("PACKETS_REV");
	m_unirecIdTable.TCP_FLAGS = ur_get_id_by_name("TCP_FLAGS");
	m_unirecIdTable.TCP_FLAGS_REV = ur_get_id_by_name("TCP_FLAGS_REV");
	m_unirecIdTable.TIME_FIRST = ur_get_id_by_name("TIME_FIRST");
	m_unirecIdTable.TIME_LAST = ur_get_id_by_name("TIME_LAST");
	m_unirecIdTable.DETECT_TIME = ur_get_id_by_name("DETECT_TIME");
	m_unirecIdTable.IDP_CONTENT = ur_get_id_by_name("IDP_CONTENT");
	m_unirecIdTable.IDP_CONTENT_REV = ur_get_id_by_name("IDP_CONTENT_REV");
	m_unirecIdTable.TLS_SNI = ur_get_id_by_name("TLS_SNI");
	m_unirecIdTable.LABEL = ur_get_id_by_name("LABEL");
	m_unirecIdTable.PPI_PKT_TIMES = ur_get_id_by_name("PPI_PKT_TIMES");
	m_unirecIdTable.PPI_PKT_FLAGS = ur_get_id_by_name("PPI_PKT_FLAGS");
	m_unirecIdTable.PPI_PKT_LENGTHS = ur_get_id_by_name("PPI_PKT_LENGTHS");
	m_unirecIdTable.PPI_PKT_DIRECTIONS = ur_get_id_by_name("PPI_PKT_DIRECTIONS");
	m_unirecIdTable.PREDICTION = ur_get_id_by_name("PREDICTION");
	m_unirecIdTable.EXPLANATION = ur_get_id_by_name("EXPLANATION");
}

} // namespace DeCrypto
