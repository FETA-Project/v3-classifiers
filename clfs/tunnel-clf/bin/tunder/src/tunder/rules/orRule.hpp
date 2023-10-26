/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Basic rule
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/rules/logicalRule.hpp"

namespace TunDer {

class OrRule : public LogicalRule {
public:
	OrRule(std::vector<std::unique_ptr<Rule>>&& rules)
		: LogicalRule("||", std::move(rules))
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
			if (rule->result()) {
				return true;
			}
		}
		return false;
	}
};

} // namespace TunDer
