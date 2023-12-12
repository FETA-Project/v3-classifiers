/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Main
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "torder/config/config.hpp"
#include "torder/processing/orchestrator.hpp"
#include "torder/settings/unirecTemplates.hpp"
#include <iostream>
#include <unirec++/unirec.hpp>
#include <unirec/unirec.h>

using namespace TorDer;
using namespace NemeaPlusPlus;

void mainLoop(
	const Config& config,
	UnirecInputInterface& inputIfc,
	UnirecOutputInterface& outputIfc)
{
	Orchestrator orchestrator(config, outputIfc);

	while (true) {
		try {
			std::optional<UnirecRecordView> unirecRecord = inputIfc.receive();
			if (!unirecRecord) {
				// Timeouted
				break;
			}

			// Pass received flow to orchestrator for further processing
			orchestrator.onFlowReceived(*unirecRecord);

		} catch (EoFException&) {
			break;
		} catch (FormatChangeException&) {
			inputIfc.changeTemplate();
			char* spec = ur_template_string(inputIfc.getTemplate());
			orchestrator.onTemplateChange(std::string(spec) + "," + UNIREC_IFC_OUTPUT_TEMPLATE);
			free(reinterpret_cast<void*>(spec));
		}
	}

	orchestrator.onEnd();
}

int main(int argc, char* argv[])
{
	std::cout << "TorDer - v" << TORDER_PROJECT_VERSION << std::endl;

	// Initialize Unirec library
	Unirec unirec({1, 1, "TorDer", "Tor Detector"});
	try {
		Config config(argc, argv);
		if (config.showHelpSeen()) {
			config.showHelp(std::cout);
			return 0;
		}

		unirec.init(argc, argv);

		// Prepare Unirec interfaces
		auto inputIfc = unirec.buildInputInterface();
		inputIfc.setRequieredFormat(UNIREC_IFC_INPUT_TEMPLATE);
		auto outputIfc = unirec.buildOutputInterface();

		// Run main loop
		mainLoop(config, inputIfc, outputIfc);
	} catch (std::exception& ex) {
		std::cout << "Exception in Main: " << ex.what() << std::endl;
	}

	return 0;
}
