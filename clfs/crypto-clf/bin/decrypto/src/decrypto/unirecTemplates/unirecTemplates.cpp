/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Unirec templates implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/unirecTemplates/unirecTemplates.hpp"

namespace DeCrypto {

namespace Templates {

std::string getInputTemplate(bool debug)
{
	if (debug) {
		return INPUT_IFC_TEMPLATE_DEBUG;
	}
	return INPUT_IFC_TEMPLATE;
}

std::string getOutputTemplate(bool debug)
{
	if (debug) {
		return OUTPUT_IFC_TEMPLATE_DEBUG;
	}
	return OUTPUT_IFC_TEMPLATE;
}

} // namespace Templates

} // namespace DeCrypto
