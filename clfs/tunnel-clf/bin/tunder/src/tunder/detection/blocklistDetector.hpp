/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Blocklist detector class
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/detector.hpp"
#include "tunder/store/counterStore.hpp"
#include <fstream>
#include <iostream>
#include <mutex>
#include <wif/classifiers/ipBlocklistClassifier.hpp>
#include <wif/utils/fs/fsWatcher.hpp>
#include <wif/utils/timer/timer.hpp>

namespace TunDer {

class BlocklistDetector : public Detector {
	class BlocklistUpdater : public WIF::Utils::TimerCallback {
	public:
		BlocklistUpdater(BlocklistDetector& classifier)
			: m_classifier(classifier)
		{
		}

		void onTick() override
		{
			using FSWatcher = WIF::Utils::FilesystemWatcher;
			auto lastModifiedTime = FSWatcher::lastTimeModified(m_classifier.blocklistFile());
			if (lastModifiedTime > m_lastModificationTime) {
				m_lastModificationTime = lastModifiedTime;
				m_classifier.updateBlocklist();
			}
		}

	private:
		BlocklistDetector& m_classifier;
		std::filesystem::file_time_type m_lastModificationTime;
	};

public:
	BlocklistDetector(
		const std::string& blocklistFile,
		unsigned tickInterval,
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: Detector(explanationId, resultId)
		, m_threshold(threshold)
		, m_store(storeSize)
		, m_blocklistFile(blocklistFile)
		, m_timer(tickInterval, std::make_unique<BlocklistUpdater>(*this))
	{
		updateBlocklist();
		m_timer.start();
	}

	DetectorID detectorID() const noexcept override { return DetectorID::BLOCKLIST; }

	const std::string& blocklistFile() const { return m_blocklistFile; }

	void updateBlocklist()
	{
		auto blocklist = loadFile(m_blocklistFile);
		std::lock_guard<std::mutex> lock(m_mutex);
		m_classifier.updateBlocklist(blocklist);
	}

	void update(StoreIndex storeIndex, const WIF::FlowFeatures& data) override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		// Perform blocklist detection of IP addresses, based on user-provided blocklist and
		// increment the current value stored in CounterStore (if positive)
		double classificationResult = m_classifier.classify(data);
		if (classificationResult > 0) {
			m_store.increment(storeIndex);
		}
	}

	DetectionResult result(StoreIndex index) const override
	{
		return m_store.get(index) >= m_threshold;
	}

	std::string explain(StoreIndex index) const override
	{
		return std::to_string(m_store.get(index)) + "x BLOCKLISTED FLOWS";
	}

	void reset(StoreIndex index) override { m_store.reset(index); }

	void setSourceFeatureIDs(const std::vector<WIF::FeatureID>& featureIDs) override
	{
		m_classifier.setFeatureSourceIDs(featureIDs);
	}

protected:
	std::vector<WIF::IpAddress> loadFile(const std::string& blocklistFile) const
	{
		std::ifstream srcFile(blocklistFile);
		if (!srcFile) {
			throw std::runtime_error(
				"BlocklistDetector::loadFile(): Source file '" + blocklistFile
				+ "' cannot be opened!");
		}

		std::vector<WIF::IpAddress> blocklist;

		std::string line;
		while (std::getline(srcFile, line)) {
			blocklist.emplace_back(line);
		}

		std::cout << "New blocklist has " << blocklist.size() << " IP addresses" << std::endl;

		return blocklist;
	}

	unsigned m_threshold;
	CounterStore m_store;
	std::string m_blocklistFile;
	WIF::IpBlocklistClassifier m_classifier;
	std::mutex m_mutex;
	WIF::Utils::Timer m_timer;
};

} // namespace TunDer
