/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Basic rule
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/rules/rule.hpp"

namespace TunDer {

class BasicRule : public Rule {
public:
	BasicRule(
		DetectorID id,
		const std::string& explanation,
		DetectionResult positiveResult = RESULT_POSITIVE)
		: Rule(explanation)
		, m_id(id)
		, m_expected(positiveResult)
	{
	}

	void registerWeakResult(DetectorID id, DetectionResult result) override
	{
		if (id == m_id) {
			m_value = result;
		}
	}

	bool result() const override { return m_value == m_expected; }

private:
	DetectorID m_id;
	DetectionResult m_value = RESULT_NEGATIVE;
	DetectionResult m_expected = RESULT_NEGATIVE;
};

} // namespace TunDer
