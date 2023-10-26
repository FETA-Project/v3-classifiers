/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Performance tracker interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <chrono>
#include <map>
#include <ostream>
#include <vector>

using chrono_time = std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>;

namespace DeCrypto {

class PerformanceTracker {
public:
	uint64_t registerNewSegment(const std::string& name);
	const std::string& segmentName(uint64_t segmentId) const;

	void segmentStart(uint64_t);
	void segmentEnd(uint64_t segmentId);
	uint64_t segmentLength(uint64_t segmentId) const;

	void dumpAll(std::ostream& os) const;

private:
	std::map<uint64_t, std::string> m_segmentNames;
	std::vector<uint64_t> m_segmentLenghts;

	chrono_time m_start;
};

} // namespace DeCrypto
