/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Performance tracker implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/performanceTracker/performanceTracker.hpp"

namespace DeCrypto {

uint64_t PerformanceTracker::registerNewSegment(const std::string& name)
{
	uint64_t id = m_segmentLenghts.size();
	m_segmentLenghts.push_back(0);
	m_segmentNames[id] = name;
	return id;
}

const std::string& PerformanceTracker::segmentName(uint64_t segmentId) const
{
	return m_segmentNames.at(segmentId);
}

void PerformanceTracker::segmentStart([[maybe_unused]] uint64_t)
{
	m_start = std::chrono::steady_clock::now();
}

void PerformanceTracker::segmentEnd(uint64_t segmentId)
{
	chrono_time t = std::chrono::steady_clock::now();
	m_segmentLenghts[segmentId]
		+= std::chrono::duration_cast<std::chrono::nanoseconds>(t - m_start).count();
}

uint64_t PerformanceTracker::segmentLength(uint64_t segmentId) const
{
	return m_segmentLenghts.at(segmentId);
}

void PerformanceTracker::dumpAll(std::ostream& os) const
{
	os << "Time Statistics" << std::endl;
	os << "========================" << std::endl;

	for (const auto& pair : m_segmentNames) {
		os << pair.second << ": " << (this->segmentLength(pair.first) / (double) 1000000000)
		   << " sec" << std::endl;
	}
}

} // namespace DeCrypto
