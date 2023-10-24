/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief WIF ID table interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <wif/flowFeatures.hpp>

namespace DeCrypto {

class WifIDTable {
public:
	WifIDTable();

	WIF::FeatureID SRC_IP;
	WIF::FeatureID DST_IP;
	WIF::FeatureID SRC_PORT;
	WIF::FeatureID DST_PORT;
	WIF::FeatureID PROTOCOL;
	WIF::FeatureID BYTES;
	WIF::FeatureID BYTES_REV;
	WIF::FeatureID PACKETS;
	WIF::FeatureID PACKETS_REV;
	WIF::FeatureID TIME_FIRST;
	WIF::FeatureID TIME_LAST;
	WIF::FeatureID TCP_FLAGS;
	WIF::FeatureID TCP_FLAGS_REV;
	WIF::FeatureID IDP_CONTENT;
	WIF::FeatureID IDP_CONTENT_REV;
	WIF::FeatureID TLS_SNI;
	WIF::FeatureID LABEL;
	WIF::FeatureID F_SENT;
	WIF::FeatureID F_RECV;
	WIF::FeatureID F_AVG_PKT_INTERVAL;
	WIF::FeatureID F_OVERALL_DURATION;
	WIF::FeatureID F_AVG_PKT_SIZE;
	WIF::FeatureID F_PUSH_RATIO;
	WIF::FeatureID F_MIN_PKT_LEN;
	WIF::FeatureID F_DATA_SYMMETRY;

	size_t size() const noexcept { return m_size; }

private:
	void init();

	size_t m_size;
};

} // namespace DeCrypto
