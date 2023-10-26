/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Evaluator implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/evaluator/evaluator.hpp"

namespace DeCrypto {

std::ostream& operator<<(std::ostream& os, const DetectorResults& detectorResults)
{
	os << "  TP = " << detectorResults.m_tp << std::endl;
	os << "  FP = " << detectorResults.m_fp << std::endl;
	os << "  FN = " << detectorResults.m_fn << std::endl;
	os << "  TN = " << detectorResults.m_tn << std::endl;
	os << "  Miners = " << detectorResults.m_miners << std::endl;
	os << "  Others = " << detectorResults.m_nonMiners << std::endl;
	os << "  Totals = " << (detectorResults.m_miners + detectorResults.m_nonMiners) << std::endl;
	return os;
}

Evaluator::Evaluator(bool debugMode)
	: m_debugMode(debugMode)
{
	m_results.resize(4);
}

void Evaluator::addResult(unsigned detectorID, bool result)
{
	if (result) {
		m_results[detectorID].m_miners++;
	} else {
		m_results[detectorID].m_nonMiners++;
	}
}

void Evaluator::addResult(unsigned detectorID, bool result, const std::string& label)
{
	if (label == "Miner") {
		m_results[detectorID].m_miners++;
		if (result) {
			m_results[detectorID].m_tp++;
		} else {
			m_results[detectorID].m_fn++;
		}
	} else if (label == "Other") {
		m_results[detectorID].m_nonMiners++;
		if (result) {
			m_results[detectorID].m_fp++;
		} else {
			m_results[detectorID].m_tn++;
		}
	}
}

void Evaluator::dumpAll(std::ostream& os) const
{
	os << "DeCrypto Results" << std::endl;

	os << " Stratum" << std::endl;
	os << m_results[STRATUM_DETECTOR];

	os << " DST" << std::endl;
	os << m_results[DST_COMBINATION];

	os << " ML" << std::endl;
	os << m_results[ML_CLASSIFIER];

	os << " Meta" << std::endl;
	DetectorResults metaRes;

	for (size_t i = 1; i < 4; ++i) {
		metaRes.m_tp += m_results[i].m_tp;
		metaRes.m_fp += m_results[i].m_fp;
		metaRes.m_fn += m_results[i].m_fn;
		metaRes.m_tn += m_results[i].m_tn;
		metaRes.m_miners += m_results[i].m_miners;
		metaRes.m_nonMiners += m_results[i].m_nonMiners;
	}

	os << metaRes;
}

} // namespace DeCrypto
