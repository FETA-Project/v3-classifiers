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
	// Prepare WIF::RegexClassifier to perform pattern matching of the short name of the
	// cryptocurrencies with names BTC, ETH, XMR, RVN, each with either . or - characters
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

	// Prepare WIF::RegexClassifier to perform pattern matching of suspicious keywords
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
	// Run WIF classifiers
	double shortNameResult = m_shortNamesMatcher->classify(flow);
	double keywordsResult = m_keywordsMatcher->classify(flow);
	// Combine the result together
	return interpretResult(shortNameResult, keywordsResult);
}

double
TlsSniClassifier::interpretResult(double shortNameMatchResult, double keywordsMatchResult) const
{
	// If output of the classifier was non-zero, replace it with value 1
	// Then run the average combinator: possible outputs: 0, 1/2, 1
	return m_averageCombinator->combine(
		{shortNameMatchResult > 0 ? 1.0 : 0.0, keywordsMatchResult > 0 ? 1.0 : 0.0});
}

} // namespace DeCrypto
