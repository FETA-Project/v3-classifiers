
/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Tor detector interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "torder/detection/torDetector.hpp"

#include <iostream>

namespace TorDer {

void TorDetector::TorTimerCallback::onTick()
{
	using FSWatcher = WIF::Utils::FilesystemWatcher;

	// Check if a file with Tor relays has been modified
	auto lastModifiedTime = FSWatcher::lastTimeModified(m_classifier.torRelaysFilePath());
	if (lastModifiedTime > m_lastModificationTime) {
		// If so, reload it
		m_lastModificationTime = lastModifiedTime;
		m_classifier.updateTorRelays();
	}
}

TorDetector::TorDetector(const std::string& torRelaysSrcFile, unsigned tickIntervalInSeconds)
	: m_torRelaysSrcFile(torRelaysSrcFile)
	, m_features(1)
	, m_timer(tickIntervalInSeconds, std::make_unique<TorTimerCallback>(*this))
{
	// Start the timer which checks for changes of the Tor relays file
	m_timer.start();
	// Set source IDs of the WIF blocklist classifier
	m_ipBlocklistClf.setFeatureSourceIDs({0});
}

void TorDetector::update(const WIF::FlowFeatures& flowData)
{
	const std::lock_guard<std::mutex> lock(m_mutex);

	// First perform detection in the DST IP field
	auto dstIp = flowData.get<WIF::IpAddress>(WIF_ID::DST_IP);
	m_features.set<WIF::IpAddress>(0, dstIp);
	if (m_ipBlocklistClf.classify(m_features) > 0) {
		m_result = true;
		m_direction = TOR_RELAY_IN_DST_IP;
		return;
	}

	// If there was no match, perform detection in the SRC IP field
	auto srcIp = flowData.get<WIF::IpAddress>(WIF_ID::SRC_IP);
	m_features.set<WIF::IpAddress>(0, srcIp);
	if (m_ipBlocklistClf.classify(m_features) > 0) {
		m_result = true;
		m_direction = TOR_RELAY_IN_SRC_IP;
		return;
	}

	// Store results
	m_result = false;
	m_direction = TOR_RELAY_NOWHERE;
}

void TorDetector::updateTorRelays()
{
	// Timer calls this method when a change on disk is detected and Tor relays file is reloaded
	const std::lock_guard<std::mutex> lock(m_mutex);
	auto torRelays = loadTorRelaysFile(m_torRelaysSrcFile);
	m_ipBlocklistClf.updateBlocklist(torRelays);
}

std::vector<WIF::IpAddress>
TorDetector::loadTorRelaysFile(const std::string& torRelaysSrcFile) const
{
	std::ifstream srcFile(torRelaysSrcFile);
	if (!srcFile) {
		throw std::runtime_error(
			"TorDetector::loadTorRelaysFile(): source file '" + torRelaysSrcFile
			+ "' cannot be opened!");
	}

	std::vector<WIF::IpAddress> torRelays;

	std::string line;
	while (std::getline(srcFile, line)) {
		torRelays.emplace_back(line);
	}

	std::cout << "New Tor relays blocklist has " << torRelays.size() << " IP addresses"
			  << std::endl;

	return torRelays;
}

} // namespace TorDer
