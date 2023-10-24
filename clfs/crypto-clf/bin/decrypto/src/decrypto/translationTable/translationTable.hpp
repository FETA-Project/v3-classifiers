/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Translation table interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "decrypto/translationTable/unirecIDTable.hpp"
#include "decrypto/translationTable/wifIDTable.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <unirec/unirec.h>
#include <unordered_map>
#include <vector>

namespace DeCrypto {

class TranslationTable {
public:
	TranslationTable();
	void update();

	inline const UnirecIDTable unirecIds() const noexcept { return m_unirecIdTable; }
	inline const WifIDTable wifIds() const noexcept { return m_wifIdTable; }

private:
	UnirecIDTable m_unirecIdTable;
	WifIDTable m_wifIdTable;
};

} // namespace DeCrypto
