/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Orchestrator implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tunder/processing/orchestrator.hpp"
#include "tunder/detection/confLevelDetector.hpp"
#include "tunder/detection/portDetector.hpp"
#include "tunder/settings/ipRangesLoader.hpp"
#include "tunder/settings/wifTemplate.hpp"
#include "tunder/utils/ipConvertor.hpp"
#include <iostream>

using UrTime = NemeaPlusPlus::UrTime;

namespace TunDer {

Orchestrator::Orchestrator(
	const Config& config,
	UnirecIDTable& unirecIDTable,
	OutputInterface& outputIfc)
	: m_config(config)
	, m_unirecIDTable(unirecIDTable)
	, m_outIfc(outputIfc)
{
	m_windowSize = m_config.timeWindowSize();

	IpRangesLoader ipRangesLoader(m_config.ipRangesFile());
	m_observedRanges = ipRangesLoader.loadedIpRanges();
	std::cout << "Loaded of IP Ranges : " << ipRangesLoader.loadedIpRanges().size() << std::endl;

	calculateStoreSize();

	registerDetectors();
	registerRules();

	for (const auto& rule : m_rules) {
		std::cout << std::boolalpha << "Registered Rule: " << rule->explanation() << std::endl;
	}
}

void Orchestrator::initWindow(uint64_t currentFlowTime)
{
	m_windowSet = true;
	setNextWindowEndTime(currentFlowTime);
}

void Orchestrator::setNextWindowEndTime(uint64_t currentFlowTime)
{
	m_nextWindowEndTime = currentFlowTime + m_windowSize;
}

bool Orchestrator::accept(const WIF::IpAddress& srcIp, const WIF::IpAddress& dstIp)
{
	for (const auto& range : m_observedRanges) {
		if (range.inRange(srcIp)) {
			m_isReversed = false;
			return true;
		} else if (range.inRange(dstIp)) {
			m_isReversed = true;
			return true;
		}
	}

	return false;
}

bool Orchestrator::isReversed() const noexcept
{
	return m_isReversed;
}

void Orchestrator::onFlowReceived(const WIF::FlowFeatures& data)
{
	// Use LAST_TIME value as a current timestamp, and initialize first time window
	// (if it was not already)
	auto currentFlowTime = data.get<uint64_t>(WIF_ID::TIME_LAST);
	if (!windowSet()) {
		initWindow(currentFlowTime);
	}

	// Find index, based on the IP range and IP
	StoreIndex storeIndex = recordToIndex(data);

	// Run all registered detectors
	for (auto& detector : m_detectors) {
		if (detector->accept(data)) {
			detector->update(storeIndex, data);
		}
	}

	// If time window expired, notify detectors
	if (shouldExport(currentFlowTime)) {
		for (auto& detector : m_detectors) {
			detector->onTimeWindowExpired();
		}

		// Call handler for expired time window and then set a new one
		onTimeIntervalExpired();
		setNextWindowEndTime(currentFlowTime);
	}
}

void Orchestrator::onTimeIntervalExpired()
{
	auto detectTime = UrTime::now();

	// Check every IP range and its IP addresses
	for (unsigned tableID = 0; tableID < m_storeSize.size(); ++tableID) {
		for (unsigned recordID = 0; recordID < m_storeSize.tableSize(tableID); ++recordID) {
			StoreIndex storeIndex = {tableID, recordID};

			// Evaluate each registered rule
			for (const auto& rule : m_rules) {
				for (const auto& detector : m_detectors) {
					rule->registerWeakResult(detector->detectorID(), detector->result(storeIndex));
				}

				// If rule was positive, send a message to the output unirec interface
				if (rule->result()) {
					auto& record = m_outIfc.getUnirecRecord();
					// Reconstruct the origin IP address for current IP range and identifier
					auto uIp = Utils::toNemeaIp(m_observedRanges[tableID].toIpAddress(recordID));

					record.setFieldFromType<NemeaPlusPlus::IpAddress>(uIp, m_unirecIDTable.SRC_IP);
					record.setFieldFromType<std::string>(rule->explanation(), m_unirecIDTable.RULE);
					record.setFieldFromType<UrTime>(detectTime, m_unirecIDTable.DETECT_TIME);

					for (const auto& detector : m_detectors) {
						record.setFieldFromType<std::string>(
							detector->explain(storeIndex),
							detector->explanationFieldID());
						record.setFieldFromType<uint8_t>(
							detector->result(storeIndex),
							detector->resultFieldID());
					}

					m_outIfc.send(record);
				}
			}

			// Reset stored information by each detector
			for (const auto& detector : m_detectors) {
				detector->reset(storeIndex);
			}
		}
	}

	m_outIfc.sendFlush();
}

void Orchestrator::onEnd()
{
	for (auto& detector : m_detectors) {
		detector->onTimeWindowExpired();
	}

	onTimeIntervalExpired();
}

StoreIndex Orchestrator::recordToIndex(const WIF::FlowFeatures& data) const
{
	StoreIndex storeIndex;
	const auto& ip = data.get<WIF::IpAddress>(WIF_ID::SRC_IP);

	for (unsigned rangeIdx = 0; rangeIdx < m_observedRanges.size(); ++rangeIdx) {
		if (m_observedRanges[rangeIdx].inRange(ip)) {
			storeIndex.m_tableIdx = rangeIdx;
			storeIndex.m_recordIdx = m_observedRanges[rangeIdx].toLocalIdentifier(ip);
			return storeIndex;
		}
	}

	throw std::runtime_error("IpAddress not found in protected ranges!");
}

void Orchestrator::calculateStoreSize()
{
	for (const auto& protectedRange : m_observedRanges) {
		m_storeSize.m_size++;
		m_storeSize.m_tableSizes.emplace_back(protectedRange.size());
	}
}

void Orchestrator::registerDetectors()
{
	m_detectors.push_back(std::make_unique<OpenVpnPortDetector>(
		m_config.ovpnPortThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_PORT_OVPN,
		m_unirecIDTable.EXPLANATION_PORT_OVPN));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::SRC_PORT, WIF_ID::DST_PORT});

	m_detectors.push_back(std::make_unique<WireGuardPortDetector>(
		m_config.wgPortThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_PORT_WG,
		m_unirecIDTable.EXPLANATION_PORT_WG));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::SRC_PORT, WIF_ID::DST_PORT});

	m_detectors.push_back(std::make_unique<OpenVpnConfLevelDetector>(
		m_config.ovpnConfProbaThreshold(),
		m_config.ovpnConfThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_CONF_LEVEL_OVPN,
		m_unirecIDTable.EXPLANATION_CONF_LEVEL_OVPN));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::OVPN_CONF_LEVEL});

	m_detectors.push_back(std::make_unique<WireGuardConfLevelDetector>(
		m_config.wgConfProbaThreshold(),
		m_config.wgConfThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_CONF_LEVEL_WG,
		m_unirecIDTable.EXPLANATION_CONF_LEVEL_WG));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::WG_CONF_LEVEL});

	m_detectors.push_back(std::make_unique<SSAConfLevelDetector>(
		m_config.ssaConfProbaThreshold(),
		m_config.ssaConfThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_CONF_LEVEL_SSA,
		m_unirecIDTable.EXPLANATION_CONF_LEVEL_SSA));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::SSA_CONF_LEVEL});

	m_detectors.push_back(std::make_unique<TorDetector>(
		m_config.torThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_TOR,
		m_unirecIDTable.EXPLANATION_TOR));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::TOR_DETECTED});

	m_detectors.push_back(std::make_unique<BlocklistDetector>(
		m_config.blocklistFile(),
		m_config.blocklistTickInterval(),
		m_config.blocklistThreshold(),
		m_storeSize,
		m_unirecIDTable.RESULT_BLOCKLIST,
		m_unirecIDTable.EXPLANATION_BLOCKLIST));
	m_detectors.back()->setSourceFeatureIDs({WIF_ID::SRC_IP, WIF_ID::DST_IP});
}

void Orchestrator::registerRules()
{
	// (OVPN_CONF_LEVEL == 100)
	m_rules.push_back(std::make_unique<BasicRule>(
		DetectorID::CONF_LEVEL_OVPN,
		"OVPN_CONF_LEVEL_100",
		OpenVpnConfLevelDetector::RESULT_OVPN_100));

	// (OVPN_CONF_LEVEL AND SSA_CONF_LEVEL)
	std::vector<std::unique_ptr<Rule>> ovpnSsaConfRule;
	ovpnSsaConfRule.push_back(
		std::make_unique<BasicRule>(DetectorID::CONF_LEVEL_OVPN, "CONF_LEVEL_OVPN"));
	ovpnSsaConfRule.push_back(
		std::make_unique<BasicRule>(DetectorID::CONF_LEVEL_SSA, "CONF_LEVEL_SSA"));
	m_rules.push_back(std::make_unique<AndRule>(std::move(ovpnSsaConfRule)));

	// (WG_CONF_LEVEL AND SSA_CONF_LEVEL)
	std::vector<std::unique_ptr<Rule>> wgSsaConfRule;
	wgSsaConfRule.push_back(
		std::make_unique<BasicRule>(DetectorID::CONF_LEVEL_WG, "CONF_LEVEL_WG"));
	wgSsaConfRule.push_back(
		std::make_unique<BasicRule>(DetectorID::CONF_LEVEL_SSA, "CONF_LEVEL_SSA"));
	m_rules.push_back(std::make_unique<AndRule>(std::move(wgSsaConfRule)));

	// (TOR)
	m_rules.push_back(std::make_unique<BasicRule>(DetectorID::TOR, "TOR"));

	// (BLOCKLIST)
	m_rules.push_back(std::make_unique<BasicRule>(DetectorID::BLOCKLIST, "BLOCKLIST"));

	// (OVPN_CONF_LEVEL AND OVPN_DEFAULT_PORT)
	std::vector<std::unique_ptr<Rule>> ovpnConfLevelPortRule;
	ovpnConfLevelPortRule.push_back(
		std::make_unique<BasicRule>(DetectorID::CONF_LEVEL_OVPN, "CONF_LEVEL_OVPN"));
	ovpnConfLevelPortRule.push_back(
		std::make_unique<BasicRule>(DetectorID::DEFAULT_PORT_OVPN, "DEFAULT_PORT_OVPN"));
	m_rules.push_back(std::make_unique<AndRule>(std::move(ovpnConfLevelPortRule)));

	// (WG_CONF_LEVEL AND WG_DEFAULT_PORT)
	std::vector<std::unique_ptr<Rule>> wgConfLevelPortRule;
	wgConfLevelPortRule.push_back(
		std::make_unique<BasicRule>(DetectorID::CONF_LEVEL_WG, "CONF_LEVEL_WG"));
	wgConfLevelPortRule.push_back(
		std::make_unique<BasicRule>(DetectorID::DEFAULT_PORT_WG, "DEFAULT_PORT_WG"));
	m_rules.push_back(std::make_unique<AndRule>(std::move(wgConfLevelPortRule)));
}

} // namespace TunDer
