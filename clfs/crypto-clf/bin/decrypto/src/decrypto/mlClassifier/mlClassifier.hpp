/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief ML classifier interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <unirec++/unirec.hpp>
#include <wif/classifiers/alfClassifier.hpp>
#include <wif/classifiers/scikitlearnMlClassifier.hpp>
#include <wif/reporters/unirecReporter.hpp>

namespace DeCrypto {

class MlClassifier {
public:
	MlClassifier(
		const std::string& modelPath,
		const std::string& bridgePath,
		bool useAlf,
		NemeaPlusPlus::UnirecOutputInterface& reporterIfc);
	// BYTES,BYTES_REV,PACKETS,PACKETS_REV,SENT,RECV,AVG_PKT_INTERVAL,OVERALL_DURATION,AVG_PKT_SIZE,PSH_RATIO,MIN_PKT_LEN,DATA_SYMMETRY
	void setSources(const std::vector<WIF::FeatureID>& featureIDs);
	std::vector<double> classify(const std::vector<WIF::FlowFeatures>& flows);

private:
	std::unique_ptr<WIF::Classifier> m_mlClassifier;
};

} // namespace DeCrypto
