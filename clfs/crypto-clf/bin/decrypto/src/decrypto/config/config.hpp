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

namespace DeCrypto {

class Config {
public:
	Config(int argc, char** argv);

	inline size_t bufferSize() const noexcept { return m_bufferSize; }
	inline double dstThreshold() const noexcept { return m_dstThreshold; }
	inline double mlThreshold() const noexcept { return m_mlThreshold; }
	inline const std::string& bridgePath() const noexcept { return m_bridgePath; }
	inline const std::string& modelPath() const noexcept { return m_modelPath; }
	inline bool useAlf() const noexcept { return m_useAlf; }
	inline bool tcpFlagsFilter() const noexcept { return m_tcpFlagsFilter; }
	inline bool showHelpSeen() const noexcept { return m_showHelpSeen; }
	inline bool debug() const noexcept { return m_debugMode; }

	void showHelp(std::ostream& os) const;

private:
	void parse(int argc, char** argv);

	size_t m_bufferSize = 50000;
	double m_dstThreshold = 0.03;
	double m_mlThreshold = 0.99;
	std::string m_bridgePath = "/opt/decrypto/runtime/bridge.py";
	std::string m_modelPath = "/opt/decrypto/runtime/rf.pickle";
	bool m_useAlf = false;
	bool m_tcpFlagsFilter = false;
	bool m_showHelpSeen = false;
	bool m_debugMode = false;
};

} // namespace DeCrypto
