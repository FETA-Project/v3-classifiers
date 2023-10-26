/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief IP Ranges Loader interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <fstream>
#include <iostream>
#include <vector>
#include <wif/ip/ipRange.hpp>
#include <wif/utils/string/strings.hpp>

namespace TunDer {

/**
 * @brief Observed IP ranges.
 * Every IP address from each defined range is observed, and alert is sent when suspicious behavior
 * is detected.
 * @return std::vector<WIF::IpRange>
 */

class IpRangesLoader {
public:
	IpRangesLoader(const std::string& sourceFile);

	const std::vector<WIF::IpRange>& loadedIpRanges() { return m_loadedIpRanges; }

private:
	void readFile(const std::string& sourceFilePath);
	bool isEmptyLine(const std::string& line) const;
	bool isComment(const std::string& line) const;
	bool hasTwoParts(const std::vector<std::string>& parts);
	void tryToParseIpRange(std::vector<std::string>& parts);
	std::vector<std::string> splitLineByComma(const std::string& line) const;

	std::vector<WIF::IpRange> m_loadedIpRanges;
};

} // namespace TunDer
