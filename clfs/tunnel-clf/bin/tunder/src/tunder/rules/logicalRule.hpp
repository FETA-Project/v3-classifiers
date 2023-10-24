/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Logical rule
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/rules/rule.hpp"
#include <memory>
#include <vector>

namespace TunDer {

class LogicalRule : public Rule {
public:
	LogicalRule(
		const std::string& logicalOperatorString,
		std::vector<std::unique_ptr<Rule>>&& rules)
		: Rule("")
		, m_logicalOperatorString(logicalOperatorString)
		, m_rules(std::move(rules))
	{
		buildExplanation();
	}

private:
	void buildExplanation()
	{
		if (m_rules.size() == 0) {
			m_explanation = "Empty";
		} else if (m_rules.size() == 1) {
			m_explanation = m_rules[0]->explanation();
		} else {
			m_explanation.append("(");
			m_explanation.append(m_rules[0]->explanation());
			for (unsigned ruleIdx = 0; ruleIdx < m_rules.size(); ++ruleIdx) {
				if (ruleIdx != 0) {
					m_explanation.append(" " + m_logicalOperatorString + " ");
					m_explanation.append(m_rules[ruleIdx]->explanation());
				}
			}
			m_explanation.append(")");
		}
	}

protected:
	std::string m_logicalOperatorString;
	std::vector<std::unique_ptr<Rule>> m_rules;
};

} // namespace TunDer
