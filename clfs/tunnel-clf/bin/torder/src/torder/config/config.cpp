/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Config implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "torder/config/config.hpp"

namespace TorDer {

Config::Config(int argc, char** argv)
{
	parse(argc, argv);
}

void Config::parse(int argc, char** argv)
{
	for (int argId = 1; argId < argc; ++argId) {
		if (std::strcmp(argv[argId], "--tor-relays-file") == 0) {
			m_torRelaysFilePath = argv[argId + 1];
			m_torRelaysSet = true;
			++argId;
		} else if (std::strcmp(argv[argId], "--tick-interval") == 0) {
			m_tickIntervalInSeconds = std::stoul(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "-h") == 0) {
			m_showHelpSeen = true;
		}
	}

	if (!m_torRelaysSet && !m_showHelpSeen) {
		throw std::runtime_error("Config::parse(): Tor relays file path was not set!");
	}
}

void Config::showHelp(std::ostream& os) const
{
	os << "Help" << std::endl;
	os << "========" << std::endl;

	os << "TorDer has one input interface with incoming flow data. The primary output "
		  "interface contains copy of the input flow with new fields describing detection result. "
		  "TOR_DETECTED contains `1`, if either SRC_IP or DST_IP was found on current Tor relays "
		  "file blocklist, `0` otherwise. Moreover, TOR_DIRECTION describes the direction: value "
		  "`1` is present, if DST_IP is Tor relay, `-1` is SRC_IP is Tor relay. Value `0` is set, "
		  "when Tor was not detected."
	   << std::endl;
	os << std::endl;

	os << "--tick-interval" << std::endl
	   << "   Interval in seconds, in which Tor relays file is checked for changes [unsigned]"
	   << std::endl
	   << "   Default: " << tickIntervalInSeconds() << std::endl;
	os << "--tor-relays-file" << std::endl
	   << "   Tor relays file path (formatted as one IP per line) [str]" << std::endl
	   << "   Default: None" << std::endl;
	os << std::endl;

	os << "Args must be always passed separated by space:" << std::endl;
	os << "   OK:   --tick-interval 10" << std::endl;
	os << "   FAIL: --tick-interval10" << std::endl;
}

} // namespace TorDer
