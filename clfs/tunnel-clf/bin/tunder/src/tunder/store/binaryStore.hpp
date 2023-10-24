/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Binary store
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/store/storeTypes.hpp"

namespace TunDer {

class BinaryStore {
public:
	BinaryStore(StoreSize size)
		: m_size(size)
	{
		m_store.resize(m_size.size());
		for (unsigned tableIdx = 0; tableIdx < m_size.size(); ++tableIdx) {
			m_store[tableIdx].resize(m_size.tableSize(tableIdx), 0);
		}
	}

	const StoreSize& size() const noexcept { return m_size; }

	void reset(StoreIndex index) { m_store[index.tableIndex()][index.recordIndex()] = 0; }

	void setPositive(StoreIndex index) { m_store[index.tableIndex()][index.recordIndex()] = 1; }

	void setNegative(StoreIndex index) { m_store[index.tableIndex()][index.recordIndex()] = 0; }

	bool isPositive(StoreIndex index) const
	{
		return m_store[index.tableIndex()][index.recordIndex()] == 1;
	}

	bool isNegative(StoreIndex index) const
	{
		return m_store[index.tableIndex()][index.recordIndex()] == 0;
	}

private:
	StoreSize m_size;
	std::vector<std::vector<uint8_t>> m_store;
};

} // namespace TunDer
