/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief ML classifier implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/mlClassifier/mlClassifier.hpp"

using namespace NemeaPlusPlus;
using namespace WIF;

namespace DeCrypto {

const std::string REPORTER_UNIREC_TEMPLATE
	= "ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT,double FEATURE_BYTES,double "
	  "FEATURE_BYTES_REV,double FEATURE_PACKETS,double "
	  "FEATURE_PACKETS_REV,double "
	  "FEATURE_SENT,double FEATURE_RECV,double FEATURE_AVG_PKT_INTERVAL,double "
	  "FEATURE_OVERALL_DURATION,double "
	  "FEATURE_AVG_PKT_SIZE,double FEATURE_PSH_RATIO,double FEATURE_MIN_PKT_LEN,double "
	  "FEATURE_DATA_SYMMETRY,uint64 LAST_MODEL_LOAD_TIME,double* "
	  "PREDICTED_PROBAS";

MlClassifier::MlClassifier(
	const std::string& modelPath,
	const std::string& bridgePath,
	bool useAlf,
	UnirecOutputInterface& reporterIfc)
{
	auto mlClassifier = std::make_unique<ScikitlearnMlClassifier>(bridgePath, modelPath, 1, useAlf);
	if (useAlf) {
		auto alfReporter = std::make_unique<UnirecReporter>(reporterIfc, REPORTER_UNIREC_TEMPLATE);
		m_mlClassifier
			= std::make_unique<AlfClassifier>(std::move(mlClassifier), std::move(alfReporter), 30);
	} else {
		m_mlClassifier = std::move(mlClassifier);
	}
}

void MlClassifier::setSources(const std::vector<FeatureID>& featureIDs)
{
	m_mlClassifier->setFeatureSourceIDs(featureIDs);
}

std::vector<double> MlClassifier::classify(const std::vector<FlowFeatures>& flows)
{
	return m_mlClassifier->classify(flows);
}

} // namespace DeCrypto
