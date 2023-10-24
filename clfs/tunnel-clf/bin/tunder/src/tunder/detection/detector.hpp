/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Detector class
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/detectionResult.hpp"
#include "tunder/store/storeTypes.hpp"
#include <unirec/unirec.h>
#include <wif/flowFeatures.hpp>

namespace TunDer {

enum class DetectorID {
	CONF_LEVEL_OVPN,
	CONF_LEVEL_WG,
	CONF_LEVEL_SSA,
	DEFAULT_PORT_OVPN,
	DEFAULT_PORT_WG,
	TOR,
	BLOCKLIST
};

class Detector {
public:
	Detector(ur_field_id_t explanationId, ur_field_id_t resultId)
		: m_explanationId(explanationId)
		, m_resultId(resultId)
	{
	}

	virtual ~Detector() = default;

	virtual DetectorID detectorID() const noexcept = 0;

	// Called by Orchestrator when new flow is received, serves as prefilter
	virtual bool accept([[maybe_unused]] const WIF::FlowFeatures& data) const { return true; }

	// Called by Orchestrator when new flow is received and accepted by Detector
	virtual void update(StoreIndex storeIndex, const WIF::FlowFeatures& data) = 0;

	// Called by Orchestrator to get weak detection result
	virtual DetectionResult result(StoreIndex index) const = 0;

	// Called by Orchestrator to get an explanation of the weak detection result
	virtual std::string explain([[maybe_unused]] StoreIndex index) const { return ""; }

	// Called by Orchestrator after time window was processed to clear store
	virtual void reset(StoreIndex index) = 0;

	virtual void setSourceFeatureIDs(const std::vector<WIF::FeatureID>& featureIDs) = 0;

	// Detectors can override this method, to finalize their detection processes, right before the
	// result checking and combination
	// Called before export by Orchestrator
	virtual void onTimeWindowExpired() {};

	ur_field_id_t explanationFieldID() const noexcept { return m_explanationId; }

	ur_field_id_t resultFieldID() const noexcept { return m_resultId; }

protected:
	ur_field_id_t m_explanationId;
	ur_field_id_t m_resultId;
};

} // namespace TunDer
