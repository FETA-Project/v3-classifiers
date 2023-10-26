/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief TLS SNI classifier interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/tlsSniClassifier/tlsSniClassifier.hpp"

using namespace WIF;

namespace DeCrypto {

TlsSniClassifier::TlsSniClassifier()
{
	m_shortNamesMatcher = std::make_unique<RegexClassifier>(
		RegexPattern(
			{
				"\\.btc",
				"btc\\.",
				"\\-btc",
				"btc\\-",
				"\\.eth",
				"eth\\.",
				"\\-eth",
				"eth\\-",
				"\\.xmr",
				"xmr\\.",
				"\\-xmr",
				"xmr\\-",
				"\\.rvn",
				"rvn\\.",
				"\\-rvn",
				"rvn\\-",
			},
			RegexPattern::PatternMatchMode::ANY),
		std::make_unique<SumCombinator>());

	m_keywordsMatcher = std::make_unique<RegexClassifier>(
		RegexPattern({"mine", "pool", "mining"}, RegexPattern::PatternMatchMode::ANY),
		std::make_unique<SumCombinator>());

	m_averageCombinator = std::make_unique<AverageCombinator>();
}

void TlsSniClassifier::setSources(const std::vector<WIF::FeatureID>& featureIDs)
{
	m_shortNamesMatcher->setFeatureSourceIDs(featureIDs);
	m_keywordsMatcher->setFeatureSourceIDs(featureIDs);
}

double TlsSniClassifier::classify(const WIF::FlowFeatures& flow)
{
	double shortNameResult = m_shortNamesMatcher->classify(flow);
	double keywordsResult = m_keywordsMatcher->classify(flow);
	return interpretResult(shortNameResult, keywordsResult);
}

double
TlsSniClassifier::interpretResult(double shortNameMatchResult, double keywordsMatchResult) const
{
	return m_averageCombinator->combine(
		{shortNameMatchResult > 0 ? 1.0 : 0.0, keywordsMatchResult > 0 ? 1.0 : 0.0});
}

} // namespace DeCrypto
