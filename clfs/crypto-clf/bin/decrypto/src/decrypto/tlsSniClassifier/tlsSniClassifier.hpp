/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief TLS SNI classifier interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <memory>
#include <wif/classifiers/regexClassifier.hpp>
#include <wif/combinators/averageCombinator.hpp>
#include <wif/combinators/sumCombinator.hpp>
#include <wif/regex/regexPattern.hpp>

namespace DeCrypto {

class TlsSniClassifier {
public:
	TlsSniClassifier();
	void setSources(const std::vector<WIF::FeatureID>& featureIDs);
	double classify(const WIF::FlowFeatures& flow);

private:
	inline double interpretResult(double shortNameMatchResult, double keywordsMatchResult) const;

	std::unique_ptr<WIF::RegexClassifier> m_shortNamesMatcher;
	std::unique_ptr<WIF::RegexClassifier> m_keywordsMatcher;
	std::unique_ptr<WIF::AverageCombinator> m_averageCombinator;
};

} // namespace DeCrypto
