
/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Tor detector interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "torder/settings/wifTable.hpp"
#include <fstream>
#include <mutex>
#include <unirec++/unirec.hpp>
#include <wif/classifiers/ipBlocklistClassifier.hpp>
#include <wif/utils/fs/fsWatcher.hpp>
#include <wif/utils/timer/timer.hpp>

namespace TorDer {

class TorDetector {
	class TorTimerCallback : public WIF::Utils::TimerCallback {
	public:
		TorTimerCallback(TorDetector& classifier)
			: m_classifier(classifier)
		{
		}

		void onTick() override;

	private:
		TorDetector& m_classifier;
		std::filesystem::file_time_type m_lastModificationTime;
	};

public:
	TorDetector(const std::string& torRelaysSrcFile, unsigned tickIntervalInSeconds);

	void update(const WIF::FlowFeatures& flowData);

	bool result() const noexcept { return m_result; }
	int8_t direction() const noexcept { return m_direction; }

	void updateTorRelays();
	const std::string& torRelaysFilePath() const noexcept { return m_torRelaysSrcFile; }

private:
	constexpr static int8_t TOR_RELAY_IN_DST_IP = 1;
	constexpr static int8_t TOR_RELAY_IN_SRC_IP = -1;
	constexpr static int8_t TOR_RELAY_NOWHERE = 0;

	std::vector<WIF::IpAddress> loadTorRelaysFile(const std::string& torRelaysSrcFile) const;

	bool m_result = false;
	int8_t m_direction = TOR_RELAY_NOWHERE;
	std::string m_torRelaysSrcFile;
	WIF::FlowFeatures m_features;
	WIF::IpBlocklistClassifier m_ipBlocklistClf;

	std::mutex m_mutex;
	WIF::Utils::Timer m_timer;
};

} // namespace TorDer
