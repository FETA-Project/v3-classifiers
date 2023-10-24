/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Orchestrator interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/blocklistDetector.hpp"
#include "tunder/detection/confLevelDetector.hpp"
#include "tunder/detection/portDetector.hpp"
#include "tunder/detection/torDetector.hpp"
#include "tunder/rules/andRule.hpp"
#include "tunder/rules/basicRule.hpp"
#include "tunder/rules/orRule.hpp"
#include "tunder/settings/config.hpp"
#include "tunder/settings/ipRangesLoader.hpp"
#include "tunder/settings/unirecIDTable.hpp"
#include <memory>
#include <unirec++/unirec.hpp>
#include <unirec/unirec.h>
#include <vector>
#include <wif/flowFeatures.hpp>
#include <wif/ip/ipRange.hpp>

namespace TunDer {

class Orchestrator {
	using OutputInterface = NemeaPlusPlus::UnirecOutputInterface;

public:
	Orchestrator(const Config& config, UnirecIDTable& unirecIDTable, OutputInterface& outputIfc);

	void initWindow(uint64_t currentFlowTime);
	void setNextWindowEndTime(uint64_t currentFlowTime);

	bool accept(const WIF::IpAddress& srcIp, const WIF::IpAddress& dstIp);
	bool isReversed() const noexcept;

	void onFlowReceived(const WIF::FlowFeatures& data);
	void onTimeIntervalExpired();
	void onEnd();

	bool windowSet() const noexcept { return m_windowSet; }

	bool shouldExport(uint64_t currentFlowTime) const noexcept
	{
		return currentFlowTime > m_nextWindowEndTime;
	}

	StoreIndex recordToIndex(const WIF::FlowFeatures& data) const;

private:
	void calculateStoreSize();
	void registerDetectors();
	void registerRules();

	const Config& m_config;

	bool m_windowSet = false;
	uint64_t m_nextWindowEndTime;
	uint32_t m_windowSize;

	StoreSize m_storeSize;
	std::vector<WIF::IpRange> m_observedRanges;
	bool m_isReversed = false;

	UnirecIDTable& m_unirecIDTable;
	OutputInterface& m_outIfc;

	std::vector<std::unique_ptr<Detector>> m_detectors;
	std::vector<std::unique_ptr<Rule>> m_rules;
};

} // namespace TunDer
