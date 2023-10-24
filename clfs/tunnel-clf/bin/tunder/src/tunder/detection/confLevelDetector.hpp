/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Confidence Level Detector
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/detector.hpp"
#include "tunder/store/binaryStore.hpp"
#include "tunder/store/counterStore.hpp"

namespace TunDer {

class ConfLevelDetector : public Detector {
public:
	ConfLevelDetector(
		unsigned confidenceThreshold,
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: Detector(explanationId, resultId)
		, m_confidenceThreshold(confidenceThreshold)
		, m_threshold(threshold)
		, m_store(storeSize)
	{
	}

	void update(StoreIndex storeIndex, const WIF::FlowFeatures& data) override
	{
		if (data.get<uint16_t>(m_sourceFeatureID) >= m_confidenceThreshold) {
			m_store.increment(storeIndex);
		}
	}

	DetectionResult result(StoreIndex index) const override
	{
		return m_store.get(index) >= m_threshold;
	}

	std::string explain(StoreIndex index) const override
	{
		return std::to_string(m_store.get(index))
			+ "x CONF_LEVEL >= " + std::to_string(m_confidenceThreshold);
	}

	void reset(StoreIndex index) override { m_store.reset(index); }

	void setSourceFeatureIDs(const std::vector<WIF::FeatureID>& featureIDs) override
	{
		if (featureIDs.size() != 1) {
			throw std::runtime_error(
				"ConfLevelDetector::setSources() - Invalid numver of source feature IDs!");
		}
		m_sourceFeatureID = featureIDs[0];
	}

protected:
	unsigned m_confidenceThreshold;
	unsigned m_threshold;
	CounterStore m_store;
	WIF::FeatureID m_sourceFeatureID;
};

class OpenVpnConfLevelDetector : public ConfLevelDetector {
public:
	static constexpr DetectionResult RESULT_OVPN_100 = 2;

	OpenVpnConfLevelDetector(
		unsigned confidenceThreshold,
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: ConfLevelDetector(confidenceThreshold, threshold, storeSize, resultId, explanationId)
		, m_store(storeSize)
	{
	}

	DetectorID detectorID() const noexcept override { return DetectorID::CONF_LEVEL_OVPN; }

	void update(StoreIndex storeIndex, const WIF::FlowFeatures& data) override
	{
		ConfLevelDetector::update(storeIndex, data);
		if (data.get<uint16_t>(m_sourceFeatureID) == 100) {
			m_store.setPositive(storeIndex);
		}
	}

	DetectionResult result(StoreIndex index) const override
	{
		if (m_store.isPositive(index)) {
			return RESULT_OVPN_100;
		}

		return ConfLevelDetector::result(index);
	}

	std::string explain(StoreIndex index) const override
	{
		std::string explanation = "";
		if (m_store.isPositive(index)) {
			explanation.append(" and OVPN_CONF_LEVEL 100% SEEN");
		}
		return ConfLevelDetector::explain(index) + explanation;
	}

private:
	BinaryStore m_store;
};

class WireGuardConfLevelDetector : public ConfLevelDetector {
public:
	WireGuardConfLevelDetector(
		unsigned confidenceThreshold,
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: ConfLevelDetector(confidenceThreshold, threshold, storeSize, resultId, explanationId)
	{
	}

	DetectorID detectorID() const noexcept override { return DetectorID::CONF_LEVEL_WG; }
};

class SSAConfLevelDetector : public ConfLevelDetector {
public:
	SSAConfLevelDetector(
		unsigned confidenceThreshold,
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: ConfLevelDetector(confidenceThreshold, threshold, storeSize, resultId, explanationId)
	{
	}

	DetectorID detectorID() const noexcept override { return DetectorID::CONF_LEVEL_SSA; }
};

} // namespace TunDer
