/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Meta classifier interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "decrypto/config/config.hpp"
#include "decrypto/mlClassifier/mlClassifier.hpp"
#include "decrypto/performanceTracker/performanceTracker.hpp"
#include "decrypto/stratumDetector/stratumDetector.hpp"
#include "decrypto/tlsSniClassifier/tlsSniClassifier.hpp"
#include "decrypto/translationTable/translationTable.hpp"
#include <unirec++/unirec.hpp>
#include <wif/combinators/binaryDSTCombinator.hpp>
#include <wif/flowFeatures.hpp>

namespace DeCrypto {

using FlowID = unsigned;

constexpr unsigned STRATUM_RESULT_ID = 0;
constexpr unsigned TLS_SNI_SCORE_ID = 1;
constexpr unsigned ML_PROBA_ID = 2;
constexpr unsigned DST_RESULT_ID = 3;

class MetaClassifier {
public:
	MetaClassifier(
		const Config& config,
		PerformanceTracker& pt,
		NemeaPlusPlus::UnirecOutputInterface& reporterIfc);

	// IDP_CONTENT_ID,IDP_CONTENT_REV_ID,TLS_SNI_ID,BYTES,BYTES_REV,PACKETS,PACKETS_REV,SENT,RECV,AVG_PKT_INTERVAL,OVERALL_DURATION,AVG_PKT_SIZE,PSH_RATIO,MIN_PKT_LEN,DATA_SYMMETRY,TCP_FLAGS,TCP_FLAGS_REV
	void setSources(const WifIDTable& idTable);
	std::vector<std::vector<double>> classify(const std::vector<WIF::FlowFeatures>& flows);

private:
	inline bool tcpFlagsSatisfied(uint8_t flags) const { return !((flags & 1) || (flags & 4)); }
	inline bool tcpFlagsFilterSatisfied(const WIF::FlowFeatures& flow) const
	{
		if (flow.get<std::string>(m_tlsSniId).size() > 0) {
			return true;
		}

		return tcpFlagsSatisfied(flow.get<uint8_t>(m_tcpFlagsId))
			&& tcpFlagsSatisfied(flow.get<uint8_t>(m_tcpFlagsRevId));
	}
	inline bool furtherProcessFlow(double stratumResult, const WIF::FlowFeatures& flow) const
	{
		return stratumResult == 0 && (!m_flagsFilterActive || tcpFlagsFilterSatisfied(flow));
	}

	size_t m_tlsSniId;
	size_t m_tcpFlagsId;
	size_t m_tcpFlagsRevId;

	PerformanceTracker& m_perfTracker;
	uint64_t m_ptStratumId;
	uint64_t m_ptTlsId;
	uint64_t m_ptMlId;

	// If active, flows with EMPTY SNI, which contain TCP RST/FIN, are dropped
	bool m_flagsFilterActive = false;

	const Config& m_config;
	std::unique_ptr<WIF::BinaryDSTCombinator> m_dstCombinator;
	std::unique_ptr<StratumDetector> m_stratumDetector;
	std::unique_ptr<TlsSniClassifier> m_tlsSniClassifier;
	std::unique_ptr<MlClassifier> m_mlClassifier;
};

} // namespace DeCrypto
