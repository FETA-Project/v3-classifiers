/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Counter store
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/store/storeTypes.hpp"

namespace TunDer {

// CounterStore is a class for storing unsigned int for each index
// (for example nubmer of actions seen)
class CounterStore {
public:
	CounterStore(StoreSize size)
		: m_size(size)
	{
		m_store.resize(m_size.size());
		for (unsigned tableIdx = 0; tableIdx < m_size.size(); ++tableIdx) {
			m_store[tableIdx].resize(m_size.tableSize(tableIdx), 0);
		}
	}

	const StoreSize& size() const noexcept { return m_size; }

	unsigned get(StoreIndex index) const
	{
		return m_store[index.tableIndex()][index.recordIndex()];
	}

	void reset(StoreIndex index) { m_store[index.tableIndex()][index.recordIndex()] = 0; }

	void add(StoreIndex index, unsigned value)
	{
		m_store[index.tableIndex()][index.recordIndex()] += value;
	}

	void increment(StoreIndex index) { m_store[index.tableIndex()][index.recordIndex()] += 1; }

private:
	StoreSize m_size;
	std::vector<std::vector<unsigned>> m_store;
};

} // namespace TunDer
