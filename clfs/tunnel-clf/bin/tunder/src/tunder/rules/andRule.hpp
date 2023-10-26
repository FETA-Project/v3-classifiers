/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief And rule
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/rules/logicalRule.hpp"

namespace TunDer {

class AndRule : public LogicalRule {
public:
	AndRule(std::vector<std::unique_ptr<Rule>>&& rules)
		: LogicalRule("&&", std::move(rules))
	{
	}

	void registerWeakResult(DetectorID id, DetectionResult result) override
	{
		for (auto& rule : m_rules) {
			rule->registerWeakResult(id, result);
		}
	}

	bool result() const override
	{
		for (const auto& rule : m_rules) {
			if (!rule->result()) {
				return false;
			}
		}
		return true;
	}
};

} // namespace TunDer
