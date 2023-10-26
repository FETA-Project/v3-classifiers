/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Meta classifier implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/metaClassifier/metaClassifier.hpp"

using namespace NemeaPlusPlus;

namespace DeCrypto {

MetaClassifier::MetaClassifier(
	const Config& config,
	PerformanceTracker& perfTracker,
	UnirecOutputInterface& reporterIfc)
	: m_perfTracker(perfTracker)
	, m_config(config)
	, m_mlClassifier(std::make_unique<MlClassifier>(
		  config.modelPath(),
		  config.bridgePath(),
		  config.useAlf(),
		  reporterIfc))
{
	m_flagsFilterActive = config.tcpFlagsFilter();

	m_dstCombinator = std::make_unique<WIF::BinaryDSTCombinator>();
	m_stratumDetector = std::make_unique<StratumDetector>();
	m_tlsSniClassifier = std::make_unique<TlsSniClassifier>();

	m_ptStratumId = m_perfTracker.registerNewSegment("Stratum Detector");
	m_ptTlsId = m_perfTracker.registerNewSegment("TLS SNI Classifier");
	m_ptMlId = m_perfTracker.registerNewSegment("ML Classifier");
}

void MetaClassifier::setSources(const WifIDTable& idTable)
{
	m_tlsSniId = idTable.TLS_SNI;
	m_tcpFlagsId = idTable.TCP_FLAGS;
	m_tcpFlagsRevId = idTable.TCP_FLAGS_REV;

	// IDP_CONTENT_ID, IDP_CONTENT_REV_ID
	m_stratumDetector->setSources({idTable.IDP_CONTENT, idTable.IDP_CONTENT_REV});
	// TLS_SNI_ID
	m_tlsSniClassifier->setSources({idTable.TLS_SNI});
	// BYTES,BYTES_REV,PACKETS,PACKETS_REV,SENT,RECV,AVG_PKT_INTERVAL,OVERALL_DURATION,AVG_PKT_SIZE,PSH_RATIO,MIN_PKT_LEN,DATA_SYMMETRY

	std::vector<WIF::FeatureID> mlFeatures;
	if (m_config.useAlf()) {
		mlFeatures.push_back(idTable.SRC_IP);
		mlFeatures.push_back(idTable.SRC_PORT);
		mlFeatures.push_back(idTable.DST_IP);
		mlFeatures.push_back(idTable.DST_PORT);
	}

	mlFeatures.push_back(idTable.BYTES);
	mlFeatures.push_back(idTable.BYTES_REV);
	mlFeatures.push_back(idTable.PACKETS);
	mlFeatures.push_back(idTable.PACKETS_REV);
	mlFeatures.push_back(idTable.F_SENT);
	mlFeatures.push_back(idTable.F_RECV);
	mlFeatures.push_back(idTable.F_AVG_PKT_INTERVAL);
	mlFeatures.push_back(idTable.F_OVERALL_DURATION);
	mlFeatures.push_back(idTable.F_AVG_PKT_SIZE);
	mlFeatures.push_back(idTable.F_PUSH_RATIO);
	mlFeatures.push_back(idTable.F_MIN_PKT_LEN);
	mlFeatures.push_back(idTable.F_DATA_SYMMETRY);

	m_mlClassifier->setSources(mlFeatures);
}

std::vector<std::vector<double>>
MetaClassifier::classify(const std::vector<WIF::FlowFeatures>& flows)
{
	std::vector<std::vector<double>> overallResults(flows.size(), std::vector<double>(4, 0.0));

	m_perfTracker.segmentStart(m_ptStratumId);
	std::vector<double> stratumResults = m_stratumDetector->classify(flows);
	m_perfTracker.segmentEnd(m_ptStratumId);

	std::vector<WIF::FlowFeatures> nextProcessBuffer;
	nextProcessBuffer.reserve(flows.size());
	std::vector<FlowID> nextProcessIdxs;
	nextProcessIdxs.reserve(flows.size());

	for (FlowID flowId = 0; flowId < stratumResults.size(); ++flowId) {
		// Copy STRATUM DETECTOR result
		overallResults[flowId][STRATUM_RESULT_ID] = stratumResults[flowId];
		// If no STRATUM, mark it for further next processing
		if (furtherProcessFlow(stratumResults[flowId], flows[flowId])) {
			nextProcessIdxs.push_back(flowId);
			nextProcessBuffer.emplace_back(flows[flowId]);
		}
	}

	// Invoke ML CLASSIFIER
	std::vector<double> mlProbas;
	if (nextProcessIdxs.size() > 0) {
		m_perfTracker.segmentStart(m_ptMlId);
		mlProbas = m_mlClassifier->classify(nextProcessBuffer);
		m_perfTracker.segmentEnd(m_ptMlId);
	}

	// Complete results
	for (FlowID flowId = 0; flowId < nextProcessIdxs.size(); ++flowId) {
		FlowID globalIdx = nextProcessIdxs[flowId];
		if (nextProcessBuffer[flowId].get<std::string>(m_tlsSniId).size() == 0) {
			overallResults[globalIdx][TLS_SNI_SCORE_ID] = 0.0;
			overallResults[globalIdx][ML_PROBA_ID] = mlProbas[flowId];
			overallResults[globalIdx][DST_RESULT_ID] = 0.0;
		} else {
			// Invoke TLS SNI CLASSIFIER
			m_perfTracker.segmentStart(m_ptTlsId);
			double tlsSniScore = m_tlsSniClassifier->classify(nextProcessBuffer[flowId]);
			m_perfTracker.segmentEnd(m_ptTlsId);

			double dstRes = m_dstCombinator->combine(std::vector<double> {
				tlsSniScore,
				mlProbas[flowId],
			});

			overallResults[globalIdx][TLS_SNI_SCORE_ID] = tlsSniScore;
			overallResults[globalIdx][ML_PROBA_ID] = mlProbas[flowId];
			overallResults[globalIdx][DST_RESULT_ID] = dstRes;
		}
	}

	return overallResults;
}

} // namespace DeCrypto
