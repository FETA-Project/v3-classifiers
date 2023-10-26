/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief IP Ranges Loader implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tunder/settings/ipRangesLoader.hpp"

namespace TunDer {

namespace {

const char* g_defaultWhiteSpaceChars = " \t\n\r\f\v";

std::string& ltrim(std::string& s, const char* whiteSpaceChars)
{
	s.erase(0, s.find_first_not_of(whiteSpaceChars));
	return s;
}

std::string& rtrim(std::string& s, const char* whiteSpaceChars)
{
	s.erase(s.find_last_not_of(whiteSpaceChars) + 1);
	return s;
}

std::string& trim(std::string& s, const char* whiteSpaceChars = g_defaultWhiteSpaceChars)
{
	return ltrim(rtrim(s, whiteSpaceChars), whiteSpaceChars);
}

} // namespace

IpRangesLoader::IpRangesLoader(const std::string& sourceFile)
{
	readFile(sourceFile);
}

bool IpRangesLoader::isEmptyLine(const std::string& line) const
{
	return line.empty();
}

bool IpRangesLoader::isComment(const std::string& line) const
{
	return line[0] == '#';
}

std::vector<std::string> IpRangesLoader::splitLineByComma(const std::string& line) const
{
	return WIF::Utils::Strings::splitStringBy(line, ",");
}

bool IpRangesLoader::hasTwoParts(const std::vector<std::string>& parts)
{
	return parts.size() == 2;
}

void IpRangesLoader::tryToParseIpRange(std::vector<std::string>& parts)
{
	try {
		auto netAddress = trim(parts[0]);
		auto netMask = trim(parts[1]);
		m_loadedIpRanges.emplace_back(netAddress, netMask);
	} catch (WIF::IpAddress::FormatError&) {
		std::cerr << "IpRangesLoader::tryToParseIpRange(): Net address mask '" + parts[0]
				+ "' and mask '" + parts[1] + "' failed to parse. Skipping..."
				  << std::endl;
	}
}

void IpRangesLoader::readFile(const std::string& sourceFilePath)
{
	std::ifstream sourceFile(sourceFilePath);
	if (!sourceFile) {
		throw std::runtime_error(
			"IpRangesLoader::readFile(): Source file '" + sourceFilePath
			+ "' could not be opened!");
	}

	std::string line;
	while (std::getline(sourceFile, line)) {
		auto& trimmedLine = trim(line);
		if (isEmptyLine(trimmedLine) || isComment(trimmedLine)) {
			continue;
		}

		auto lineParts = splitLineByComma(trimmedLine);
		if (hasTwoParts(lineParts)) {
			tryToParseIpRange(lineParts);
		}
	}
}

} // namespace TunDer
