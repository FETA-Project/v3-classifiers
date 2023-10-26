/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Port detector class
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/detector.hpp"
#include "tunder/store/counterStore.hpp"

namespace TunDer {

class PortDetector : public Detector {
public:
	PortDetector(
		uint16_t port,
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: Detector(explanationId, resultId)
		, m_port(port)
		, m_threshold(threshold)
		, m_store(storeSize)
	{
	}

	void update(StoreIndex storeIndex, const WIF::FlowFeatures& data) override
	{
		for (const auto featureID : m_sourceFeatureIDs) {
			if (data.get<uint16_t>(featureID) == m_port) {
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
		return std::to_string(m_store.get(index)) + "x PORT " + std::to_string(m_port);
	}

	void reset(StoreIndex index) override { m_store.reset(index); }

	void setSourceFeatureIDs(const std::vector<WIF::FeatureID>& featureIDs) override
	{
		m_sourceFeatureIDs = featureIDs;
	}

protected:
	uint16_t m_port;
	unsigned m_threshold;
	CounterStore m_store;
	std::vector<WIF::FeatureID> m_sourceFeatureIDs;
};

class OpenVpnPortDetector : public PortDetector {
public:
	constexpr static uint16_t OVPN_DEFAULT_PORT = 1194;

	OpenVpnPortDetector(
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: PortDetector(OVPN_DEFAULT_PORT, threshold, storeSize, resultId, explanationId)
	{
	}

	DetectorID detectorID() const noexcept override { return DetectorID::DEFAULT_PORT_OVPN; }
};

class WireGuardPortDetector : public PortDetector {
public:
	constexpr static uint16_t WIREGUARD_DEFAULT_PORT = 51820;

	WireGuardPortDetector(
		unsigned threshold,
		StoreSize storeSize,
		ur_field_id_t resultId,
		ur_field_id_t explanationId)
		: PortDetector(WIREGUARD_DEFAULT_PORT, threshold, storeSize, resultId, explanationId)
	{
	}

	DetectorID detectorID() const noexcept override { return DetectorID::DEFAULT_PORT_WG; }
};

} // namespace TunDer
