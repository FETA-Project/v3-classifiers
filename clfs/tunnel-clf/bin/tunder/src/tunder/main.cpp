/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Main
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tunder/processing/orchestrator.hpp"
#include "tunder/processing/transformer.hpp"
#include "tunder/settings/config.hpp"
#include "tunder/settings/unirecIDTable.hpp"
#include "tunder/settings/unirecTemplates.hpp"
#include <iostream>
#include <unirec++/unirec.hpp>

using namespace TunDer;
using namespace NemeaPlusPlus;

void mainLoop(
	const Config& config,
	UnirecInputInterface& inputIfc,
	UnirecOutputInterface& outputIfc)
{
	UnirecIDTable unirecIDTable;
	Orchestrator orchestrator(config, unirecIDTable, outputIfc);
	Transformer transformer(unirecIDTable);

	while (true) {
		try {
			// Receive new unirec record
			std::optional<UnirecRecordView> unirecRecord = inputIfc.receive();
			if (!unirecRecord) {
				// Timeouted
				break;
			}

			auto srcIp = transformer.extractSrcIp(*unirecRecord);
			auto dstIp = transformer.extractDstIp(*unirecRecord);

			// Check if at least one of the SRC and DST IPs is part of observed IP ranges, otherwise
			// do not process it
			if (orchestrator.accept(srcIp, dstIp)) {
				// Extract needed data from unirec record into WIF internal data structure
				auto flowFeatures = transformer.transform(*unirecRecord, orchestrator.isReversed());
				// Pass it to the orchestrator
				orchestrator.onFlowReceived(flowFeatures);
			}
		} catch (EoFException&) {
			break;
		} catch (FormatChangeException&) {
			inputIfc.changeTemplate();
			unirecIDTable.update();
		}
	}

	orchestrator.onEnd();
}

int main(int argc, char* argv[])
{
	// Parse input arguments and configure the detector
	Config config(argc, argv);
	if (config.showHelpSeen()) {
		config.showHelp(std::cout);
		return 0;
	}

	config.printConfiguration(std::cout);

	// Initialize Unirec library
	Unirec unirec({1, 1, "TunDer", "Communication Tunnel Detector"});
	// try {
	unirec.init(argc, argv);

	// Prepare input and output interfaces
	auto inputIfc = unirec.buildInputInterface();
	inputIfc.setRequieredFormat(UNIREC_IFC_INPUT_TEMPLATE);
	auto outputIfc = unirec.buildOutputInterface();
	outputIfc.changeTemplate(UNIREC_IFC_OUTPUT_TEMPLATE);

	// Run main loop
	mainLoop(config, inputIfc, outputIfc);
	//} catch (std::exception& ex) {
	//	std::cout << "Ex: << " << ex.what() << std::endl;
	//}

	return 0;
}
