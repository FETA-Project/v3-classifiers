/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Store type definitions
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstddef>
#include <vector>

namespace TunDer {

struct StoreSize {
	size_t size() const noexcept { return m_size; }
	size_t tableSize(unsigned tableIdx) const noexcept { return m_tableSizes[tableIdx]; }

	size_t m_size = 0;
	std::vector<size_t> m_tableSizes;
};

struct StoreIndex {
	unsigned tableIndex() const noexcept { return m_tableIdx; }
	unsigned recordIndex() const noexcept { return m_recordIdx; }

	unsigned m_tableIdx;
	unsigned m_recordIdx;
};

} // namespace TunDer
