/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Config interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstring>
#include <getopt.h>
#include <ostream>

namespace TunDer {

class Config {
public:
	Config(int argc, char** argv);

	inline unsigned timeWindowSize() const noexcept { return m_timeWindowSize; }
	inline unsigned ovpnPortThreshold() const noexcept { return m_ovpnPortThreshold; }
	inline unsigned wgPortThreshold() const noexcept { return m_wgPortThreshold; }
	inline unsigned ovpnConfProbaThreshold() const noexcept { return m_ovpnConfProbaThreshold; }
	inline unsigned ovpnConfThreshold() const noexcept { return m_ovpnConfThreshold; }
	inline unsigned wgConfProbaThreshold() const noexcept { return m_wgConfProbaThreshold; }
	inline unsigned wgConfThreshold() const noexcept { return m_wgConfThreshold; }
	inline unsigned ssaConfProbaThreshold() const noexcept { return m_ssaConfProbaThreshold; }
	inline unsigned ssaConfThreshold() const noexcept { return m_ssaConfThreshold; }
	inline unsigned torThreshold() const noexcept { return m_torThreshold; }
	inline const std::string& ipRangesFile() const noexcept { return m_ipRangesFile; }
	inline const std::string& blocklistFile() const noexcept { return m_blocklistFile; }
	inline unsigned blocklistTickInterval() const noexcept { return m_blocklistTickInterval; }
	inline unsigned blocklistThreshold() const noexcept { return m_blocklistThreshold; }
	inline bool showHelpSeen() const noexcept { return m_showHelpSeen; }
	inline bool debug() const noexcept { return m_debugMode; }

	void showHelp(std::ostream& os) const;
	void printConfiguration(std::ostream& os) const;

private:
	void parse(int argc, char** argv);

	unsigned m_timeWindowSize = 900;
	unsigned m_ovpnPortThreshold = 5;
	unsigned m_wgPortThreshold = 5;
	unsigned m_ovpnConfProbaThreshold = 50;
	unsigned m_ovpnConfThreshold = 5;
	unsigned m_wgConfProbaThreshold = 50;
	unsigned m_wgConfThreshold = 5;
	unsigned m_ssaConfProbaThreshold = 50;
	unsigned m_ssaConfThreshold = 5;
	unsigned m_torThreshold = 5;
	std::string m_ipRangesFile = "/opt/tunder/ipRanges.txt";
	std::string m_blocklistFile = "/opt/tunder/blocklist.txt";
	unsigned m_blocklistTickInterval = 30; // seconds
	unsigned m_blocklistThreshold = 5;
	bool m_showHelpSeen = false;
	bool m_debugMode = false;
};

} // namespace TunDer
