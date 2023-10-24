/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Orchestrator interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "torder/config/config.hpp"
#include "torder/detection/torDetector.hpp"
#include "torder/processing/transformer.hpp"
#include "torder/settings/unirecTable.hpp"
#include <memory>
#include <unirec++/unirec.hpp>
#include <unirec/unirec.h>
#include <vector>
#include <wif/flowFeatures.hpp>

namespace TorDer {

class Orchestrator {
	using OutputInterface = NemeaPlusPlus::UnirecOutputInterface;
	using UnirecRecordView = NemeaPlusPlus::UnirecRecordView;

public:
	Orchestrator(const Config& config, OutputInterface& outputIfc);

	void onTemplateChange(const std::string& unirecTemplate);

	void onFlowReceived(const UnirecRecordView& record);
	void onEnd();

private:
	UnirecTable m_unirecTable;
	Transformer m_transformer;
	OutputInterface& m_outIfc;

	TorDetector m_detector;
};

} // namespace TorDer
