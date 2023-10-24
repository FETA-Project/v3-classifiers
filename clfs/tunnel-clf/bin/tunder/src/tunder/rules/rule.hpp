/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Abstract rule class
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/detection/detectionResult.hpp"
#include "tunder/detection/detector.hpp"
#include <string>

namespace TunDer {

class Rule {
public:
	Rule(const std::string& explanation)
		: m_explanation(explanation)
	{
	}

	virtual ~Rule() = default;

	virtual bool result() const = 0;
	virtual void registerWeakResult(DetectorID id, DetectionResult result) = 0;
	const std::string& explanation() const noexcept { return m_explanation; }

protected:
	std::string m_explanation;
};

} // namespace TunDer
