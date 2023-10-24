/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Stratum detector implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/stratumDetector/stratumDetector.hpp"

using namespace WIF;

namespace DeCrypto {

StratumDetector::StratumDetector()
{
	m_requestMatcher = std::make_unique<RegexClassifier>(
		RegexPattern(
			{"(\"(jsonrpc|method|worker)\":\\s?\")|(params\":|mining\\.(set|not))"},
			RegexPattern::PatternMatchMode::ANY),
		std::make_unique<SumCombinator>());

	// m_responseMatcher = std::make_unique<RegexClassifier>(
	//	RegexPattern({"\"id\":", "\"result\":", "\"error\":"}, RegexPattern::PatternMatchMode::ALL),
	//	std::make_unique<SumCombinator>());
}

void StratumDetector::setSources(const std::vector<WIF::FeatureID>& featureIDs)
{
	m_requestMatcher->setFeatureSourceIDs(featureIDs);
	// m_responseMatcher->setFeatureSourceIDs(featureIDs);
}

std::vector<double> StratumDetector::classify(const std::vector<WIF::FlowFeatures>& flows)
{
	auto requestResults = m_requestMatcher->classify(flows);
	// auto responseResults = m_responseMatcher->classify(flows);

	std::vector<double> results;
	results.reserve(flows.size());

	for (const auto result : requestResults) {
		results.push_back(result > 0 ? 1 : 0);
	}

	// for (size_t matchResultId = 0; matchResultId < flows.size(); ++matchResultId) {
	//	results.push_back(
	//		requestResults[matchResultId] /*+ responseResults[matchResultId]*/ > 0 ? 1 : 0);
	// }

	return results;
}

} // namespace DeCrypto
