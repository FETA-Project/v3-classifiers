/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Main
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/config/config.hpp"
#include "decrypto/processor/processor.hpp"
#include <chrono>
#include <iostream>
#include <unirec++/unirec.hpp>

using namespace NemeaPlusPlus;
using chrono_time_t = std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>;

int main(int argc, char** argv)
{
	std::cout << "DeCrypto" << std::endl;
	std::cout << "========" << std::endl;
	std::cout << "  CryptoMiners Detector based on WIF." << std::endl;
	std::cout << "  Built " << __DATE__ << " " << __TIME__ << std::endl;
	std::cout << std::endl;

	// Parse input parameters and configure detection module
	DeCrypto::Config config(argc, argv);
	if (config.showHelpSeen()) {
		config.showHelp(std::cout);
		return 0;
	}

	/*
	 * Initialize UniRec library
	 *   Use 1 input interface for incoming flow data
	 *   Use 2 output interfaces - one for standard output, second for ALF data)
	 */
	Unirec unirec({1, 2, "DeCrypto", "Cryptominers Detector"});

	try {
		unirec.init(argc, argv);
		UnirecInputInterface inputIfc = unirec.buildInputInterface();
		UnirecOutputInterface reporterIfc = unirec.buildOutputInterface();
		UnirecOutputInterface outputIfc = unirec.buildOutputInterface();

		DeCrypto::Processor flowProcessor(config, reporterIfc);

		// Run main loop implemented in Processor::mainLoop() and measure the execution time
		chrono_time_t runTimeStart = std::chrono::steady_clock::now();
		flowProcessor.mainLoop(inputIfc, outputIfc);
		chrono_time_t runTimeEnd = std::chrono::steady_clock::now();

		auto runTime = runTimeEnd - runTimeStart;
		auto runTimeInSeconds = std::chrono::duration_cast<std::chrono::seconds>(runTime).count();
		std::cout << "Run Time: " << runTimeInSeconds << " sec" << std::endl;
	} catch (std::exception& e) {
		std::cout << "Exception in Main: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
