/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Tor detector class
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/detector.hpp"
#include "tunder/store/counterStore.hpp"

namespace TunDer {

class TorDetector : public Detector {
public:
	TorDetector(
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: Detector(explanationId, resultId)
		, m_threshold(threshold)
		, m_store(storeSize)
	{
	}

	DetectorID detectorID() const noexcept override { return DetectorID::TOR; }

	void update(StoreIndex storeIndex, const WIF::FlowFeatures& data) override
	{
		for (const auto featureID : m_sourceFeatureIDs) {
			if (data.get<uint8_t>(featureID)) {
				m_store.increment(storeIndex);
				break;
			}
		}
	}

	DetectionResult result(StoreIndex index) const override
	{
		return m_store.get(index) >= m_threshold;
	}

	std::string explain(StoreIndex index) const override
	{
		return std::to_string(m_store.get(index)) + "x TOR CONNECTIONS";
	}

	void reset(StoreIndex index) override { m_store.reset(index); }

	void setSourceFeatureIDs(const std::vector<WIF::FeatureID>& featureIDs) override
	{
		m_sourceFeatureIDs = featureIDs;
	}

protected:
	unsigned m_threshold;
	CounterStore m_store;
	std::vector<WIF::FeatureID> m_sourceFeatureIDs;
};

} // namespace TunDer
