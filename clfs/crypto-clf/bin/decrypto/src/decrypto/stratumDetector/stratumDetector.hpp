/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Stratum detector interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <memory>
#include <wif/classifiers/regexClassifier.hpp>
#include <wif/combinators/sumCombinator.hpp>
#include <wif/regex/regexPattern.hpp>

namespace DeCrypto {

class StratumDetector {
public:
	StratumDetector();
	void setSources(const std::vector<WIF::FeatureID>& featureIDs);
	std::vector<double> classify(const std::vector<WIF::FlowFeatures>& flows);

private:
	std::unique_ptr<WIF::RegexClassifier> m_requestMatcher;
	// std::unique_ptr<WIF::RegexClassifier> m_responseMatcher;
};

} // namespace DeCrypto
