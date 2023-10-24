/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Config implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tunder/settings/config.hpp"

namespace TunDer {

Config::Config(int argc, char** argv)
{
	parse(argc, argv);
}

void Config::parse(int argc, char** argv)
{
	for (int argId = 1; argId < argc; ++argId) {
		if (std::strcmp(argv[argId], "--time-window-size") == 0) {
			m_timeWindowSize = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ovpn-port-threshold") == 0) {
			m_ovpnPortThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--wg-port-threshold") == 0) {
			m_wgPortThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ovpn-conf-proba-threshold") == 0) {
			m_ovpnConfProbaThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ovpn-conf-threshold") == 0) {
			m_ovpnConfThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--wg-conf-proba-threshold") == 0) {
			m_wgConfProbaThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--wg-conf-threshold") == 0) {
			m_wgConfThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ssa-conf-proba-threshold") == 0) {
			m_ssaConfProbaThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ssa-conf-threshold") == 0) {
			m_ssaConfThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--tor-threshold") == 0) {
			m_torThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ip-ranges-file") == 0) {
			m_ipRangesFile = std::string(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--blocklist-file") == 0) {
			m_blocklistFile = std::string(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--blocklist-tick-interval") == 0) {
			m_blocklistTickInterval = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--blocklist-threshold") == 0) {
			m_blocklistThreshold = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "-h") == 0) {
			m_showHelpSeen = true;
		} else if (std::strcmp(argv[argId], "-d") == 0) {
			m_debugMode = true;
		}
	}
}

void Config::showHelp(std::ostream& os) const
{
	os << "Help" << std::endl;
	os << "========" << std::endl;

	os << "TunDer is a detector of covert communicaton tunnels. It uses {OVPN,WG,SSA}_CONF_LEVEL "
		  "fields for detection of OpenVPN and WireGuard. It consists of multiple weak "
		  "detectors: CONF_LEVEL Detector for both OVPN, WG and SSA, Default Port Detector for "
		  "both OVPN and WG, Tor Detector, and Blocklist Detector. Every detector can be "
		  "customized: threshold for number of positive flows, which has to be seen in the time "
		  "window, to consider detector in this time window to be positive. Moreover, a "
		  "probability threshold can be set for CONF_LEVEL detectors, to define needed minimal "
		  "value of CONF_LEVEL field, to consider flow positive. Results of weak detectors are "
		  "observed for each IP address defined as observed. When time interval expires, rule "
		  "matching takes place and every satisfied rule for each observed IP address generates an "
		  "alert on the output interface, which describes results and explanations for each weak "
		  "detector."
	   << std::endl
	   << std::endl;

	os << "-d" << std::endl
	   << "   Enable debug mode [-]" << std::endl
	   << "   Default: " << std::boolalpha << debug() << std::endl;
	os << "-h" << std::endl
	   << "   Display help section [-]" << std::endl
	   << "   Default: " << std::boolalpha << false << std::endl;
	os << std::endl;

	os << "--time-window-size" << std::endl
	   << "   Time Window Size of TunDer in seconds [unsigned]" << std::endl
	   << "   Default: " << timeWindowSize() << std::endl;
	os << "--ovpn-port-threshold" << std::endl
	   << "   Threshold for OVPN Port Detector [unsigned]" << std::endl
	   << "   Default: " << ovpnPortThreshold() << std::endl;
	os << "--wg-port-threshold" << std::endl
	   << "   Threshold for WireGuard Port Detector [unsigned]" << std::endl
	   << "   Default: " << wgPortThreshold() << std::endl;
	os << "--ovpn-conf-proba-threshold" << std::endl
	   << "   Minimal OVPN_CONF_LEVEL value considered positive [unsigned]" << std::endl
	   << "   Default: " << ovpnConfProbaThreshold() << std::endl;
	os << "--ovpn-conf-threshold" << std::endl
	   << "   Threshold for OVPN_CONF_LEVEL Detector [unsigned]" << std::endl
	   << "   Default: " << ovpnConfThreshold() << std::endl;
	os << "--wg-conf-proba-threshold" << std::endl
	   << "   Minimal WG_CONF_LEVEL value considered positive [unsigned]" << std::endl
	   << "   Default: " << wgConfProbaThreshold() << std::endl;
	os << "--wg-conf-threshold" << std::endl
	   << "   Threshold for WG_CONF_LEVEL Detector [unsigned]" << std::endl
	   << "   Default: " << wgConfThreshold() << std::endl;
	os << "--ssa-conf-proba-threshold" << std::endl
	   << "   Minimal SSA_CONF_LEVEL value considered positive [unsigned]" << std::endl
	   << "   Default: " << ssaConfProbaThreshold() << std::endl;
	os << "--ssa-conf-threshold" << std::endl
	   << "   Threshold for SSA_CONF_LEVEL Detector [unsigned]" << std::endl
	   << "   Default: " << ssaConfThreshold() << std::endl;
	os << "--tor-threshold" << std::endl
	   << "   Threshold for Tor Detector [unsigned]" << std::endl
	   << "   Default: " << torThreshold() << std::endl;
	os << "--ip-ranges-file" << std::endl
	   << "   Path to observed IP ranges file [string]" << std::endl
	   << "   Default: " << ipRangesFile() << std::endl;
	os << "--blocklist-file" << std::endl
	   << "   Path to blocklist file [string]" << std::endl
	   << "   Default: " << blocklistFile() << std::endl;
	os << "--blocklist-tick-interval" << std::endl
	   << "   Interval in seconds, in which blocklist file is checked for changes [unsigned]"
	   << std::endl
	   << "   Default: " << blocklistTickInterval() << std::endl;
	os << "--blocklist-threshold" << std::endl
	   << "   Threshold for Blocklist Detector [unsigned]" << std::endl
	   << "   Default: " << blocklistThreshold() << std::endl;
	os << std::endl;

	os << "Args must be always passed separated by space:" << std::endl;
	os << "   OK:   -m model.pickle" << std::endl;
	os << "   FAIL: -mmodel.pickle" << std::endl;
}

void Config::printConfiguration(std::ostream& os) const
{
	os << "TunDer - v" << TUNDER_PROJECT_VERSION << std::endl;
	os << "==============================================================" << std::endl;
	os << "Current Configuration:" << std::endl << std::endl;

	os << "Debug Mode                        : " << std::boolalpha << debug() << std::endl;
	os << "Time Window Size (seconds)        : " << timeWindowSize() << std::endl;
	os << "OVPN Port Threshold               : " << ovpnPortThreshold() << std::endl;
	os << "WG Port Threshold                 : " << wgPortThreshold() << std::endl;
	os << "OVPN_CONF_LEVEL Proba Threshold   : " << ovpnConfProbaThreshold() << std::endl;
	os << "OVPN_CONF_LEVEL Threshold         : " << ovpnConfThreshold() << std::endl;
	os << "WG_CONF_LEVEL Proba Threshold     : " << wgConfProbaThreshold() << std::endl;
	os << "WG_CONF_LEVEL Threshold           : " << wgConfThreshold() << std::endl;
	os << "SSA_CONF_LEVEL Proba Threshold    : " << ssaConfProbaThreshold() << std::endl;
	os << "SSA_CONF_LEVEL Threshold          : " << ssaConfThreshold() << std::endl;
	os << "Tor Threshold                     : " << torThreshold() << std::endl;
	os << "Observed IP Ranges File           : " << ipRangesFile() << std::endl;
	os << "Blocklist File                    : " << blocklistFile() << std::endl;
	os << "Blocklist Tick Interval (seconds) : " << blocklistTickInterval() << std::endl;
	os << "Blocklist Threshold               : " << blocklistThreshold() << std::endl;
	os << std::endl;
}

} // namespace TunDer
