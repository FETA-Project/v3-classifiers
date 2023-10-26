/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Detection result definition
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstdint>

namespace TunDer {

using DetectionResult = uint16_t;

constexpr DetectionResult RESULT_POSITIVE = 1;
constexpr DetectionResult RESULT_NEGATIVE = 0;

} // namespace TunDer
