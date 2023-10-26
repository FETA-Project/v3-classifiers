/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Evaluator interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <ostream>
#include <string>
#include <vector>

namespace DeCrypto {

struct DetectorResults {
	unsigned m_tp = 0;
	unsigned m_fp = 0;
	unsigned m_fn = 0;
	unsigned m_tn = 0;
	unsigned m_miners = 0;
	unsigned m_nonMiners = 0;

	friend std::ostream& operator<<(std::ostream& os, const DetectorResults& detectorResults);
};

class Evaluator {
public:
	constexpr static unsigned META_CLASSIFIER = 0;
	constexpr static unsigned STRATUM_DETECTOR = 1;
	constexpr static unsigned DST_COMBINATION = 2;
	constexpr static unsigned ML_CLASSIFIER = 3;
	constexpr static unsigned UNKNOWN = 4;

	Evaluator(bool debugMode);

	void addResult(unsigned detectorID, bool result);
	void addResult(unsigned detectorID, bool result, const std::string& label);

	void dumpAll(std::ostream& os) const;

private:
	bool m_debugMode;
	std::vector<DetectorResults> m_results;
};

} // namespace DeCrypto
