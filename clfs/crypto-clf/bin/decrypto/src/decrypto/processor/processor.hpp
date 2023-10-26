/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Main loop interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "decrypto/config/config.hpp"
#include "decrypto/evaluator/evaluator.hpp"
#include "decrypto/metaClassifier/metaClassifier.hpp"
#include "decrypto/performanceTracker/performanceTracker.hpp"
#include "decrypto/translationTable/translationTable.hpp"
#include "decrypto/unirecTemplates/unirecTemplates.hpp"
#include <iostream>
#include <tuple>
#include <unirec++/unirec.hpp>
#include <unirec/unirec.h>
#include <vector>
#include <wif/flowFeatures.hpp>

namespace DeCrypto {

constexpr unsigned FLOW_FEATURES_SIZE = 25;
constexpr uint8_t SENT_DIRECTION = 1;

class Processor {
public:
	Processor(const Config& config, NemeaPlusPlus::UnirecOutputInterface& reporterIfc);

	void mainLoop(
		NemeaPlusPlus::UnirecInputInterface& inputIfc,
		NemeaPlusPlus::UnirecOutputInterface& outputIfc);

private:
	bool prefilter(const NemeaPlusPlus::UnirecRecordView& flow) const;
	void doDetection(
		const std::vector<WIF::FlowFeatures>& buffer,
		NemeaPlusPlus::UnirecOutputInterface& outputIfc);
	void extractFeaturesToBuffer(
		WIF::FlowFeatures& target,
		const NemeaPlusPlus::UnirecRecordView& flow) const;

	void sendToOutput(
		NemeaPlusPlus::UnirecOutputInterface& outputIfc,
		const WIF::FlowFeatures& flow,
		bool prediction,
		const std::string& predictionPath);

	Config m_config;
	Evaluator m_evaluator;
	PerformanceTracker m_perfTracker;
	MetaClassifier m_metaClassifier;
	TranslationTable m_translationTable;
	FlowID m_nextFlowId = 0;
	std::vector<WIF::FlowFeatures> m_flowBuffer;
};

} // namespace DeCrypto
