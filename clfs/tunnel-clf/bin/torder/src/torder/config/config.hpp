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

namespace TorDer {

class Config {
public:
	Config(int argc, char** argv);

	inline unsigned tickIntervalInSeconds() const noexcept { return m_tickIntervalInSeconds; }
	inline const std::string& torRelaysFilePath() const noexcept { return m_torRelaysFilePath; }
	inline bool showHelpSeen() const noexcept { return m_showHelpSeen; }

	void showHelp(std::ostream& os) const;

private:
	void parse(int argc, char** argv);

	unsigned m_tickIntervalInSeconds = 15;
	bool m_torRelaysSet = false;
	std::string m_torRelaysFilePath;
	bool m_showHelpSeen = false;
};

} // namespace TorDer
