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
			std::optional<UnirecRecordView> unirecRecord = inputIfc.receive();
			if (!unirecRecord) {
				// Timeouted
				break;
			}

			auto srcIp = transformer.extractSrcIp(*unirecRecord);
			auto dstIp = transformer.extractDstIp(*unirecRecord);

			if (orchestrator.accept(srcIp, dstIp)) {
				auto flowFeatures = transformer.transform(*unirecRecord, orchestrator.isReversed());
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
	Config config(argc, argv);
	if (config.showHelpSeen()) {
		config.showHelp(std::cout);
		return 0;
	}

	config.printConfiguration(std::cout);

	Unirec unirec({1, 1, "TunDer", "Communication Tunnel Detector"});
	// try {
	unirec.init(argc, argv);

	auto inputIfc = unirec.buildInputInterface();
	inputIfc.setRequieredFormat(UNIREC_IFC_INPUT_TEMPLATE);
	auto outputIfc = unirec.buildOutputInterface();
	outputIfc.changeTemplate(UNIREC_IFC_OUTPUT_TEMPLATE);

	mainLoop(config, inputIfc, outputIfc);
	//} catch (std::exception& ex) {
	//	std::cout << "Ex: << " << ex.what() << std::endl;
	//}

	return 0;
}
