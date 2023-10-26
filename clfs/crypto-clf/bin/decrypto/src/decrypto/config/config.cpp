/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Config implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/config/config.hpp"

namespace DeCrypto {

Config::Config(int argc, char** argv)
{
	parse(argc, argv);
}

void Config::parse(int argc, char** argv)
{
	for (int argId = 1; argId < argc; ++argId) {
		if (std::strcmp(argv[argId], "--dst") == 0) {
			m_dstThreshold = std::atof(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "--ml") == 0) {
			m_mlThreshold = std::atof(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "-m") == 0) {
			m_modelPath = std::string(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "-b") == 0) {
			m_bridgePath = std::string(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "-h") == 0) {
			m_showHelpSeen = true;
		} else if (std::strcmp(argv[argId], "-f") == 0) {
			m_bufferSize = std::atof(argv[argId + 1]);
			++argId;
		} else if (std::strcmp(argv[argId], "-d") == 0) {
			m_debugMode = true;
		} else if (std::strcmp(argv[argId], "--no-rst-fin") == 0) {
			m_tcpFlagsFilter = true;
		} else if (std::strcmp(argv[argId], "--use-alf") == 0) {
			m_useAlf = true;
		}
	}
}

void Config::showHelp(std::ostream& os) const
{
	os << "Help" << std::endl;
	os << "========" << std::endl;

	os << "DeCrypto has one input interface with incoming flow data. The primary output "
		  "interface contains standard alerts. The secondary output interface contains ML features "
		  "and flow info - if and only if the --use-alf is specified. Otherwise this interface "
		  "should be set to 'b:'."
	   << std::endl;

	os << "  Example without ALF : decrypto -i u:flowData,u:alerts,b: <other args>" << std::endl;
	os << "  Example wit ALF     : decrypto -i u:flowData,u:alerts,u:alfData <other args>"
	   << std::endl
	   << std::endl;

	os << "-b" << std::endl
	   << "   Python Bridge Path [str]" << std::endl
	   << "   Default: " << bridgePath() << std::endl;
	os << "-d" << std::endl
	   << "   Enable debug mode" << std::endl
	   << "   Default: " << std::boolalpha << debug() << std::endl;
	os << "-f" << std::endl
	   << "   Flow Buffer Size [unsigned]" << std::endl
	   << "   Default: " << bufferSize() << std::endl;
	os << "-h" << std::endl
	   << "   Display help section [-]" << std::endl
	   << "   Default: " << std::boolalpha << false << std::endl;
	os << "-m" << std::endl
	   << "   ML Model Path, pickle format[str]" << std::endl
	   << "   Default: " << modelPath() << std::endl;

	os << "--dst" << std::endl
	   << "   DST Threshold [0..1]" << std::endl
	   << "   Default: " << dstThreshold() << std::endl;
	os << "--ml" << std::endl
	   << "   ML Threshold [0..1]" << std::endl
	   << "   Default: " << mlThreshold() << std::endl;
	os << "--no-rst-fin" << std::endl
	   << "   Filter flows with empty SNI and RST/FIN flags" << std::endl
	   << "   Default: " << std::boolalpha << tcpFlagsFilter() << std::endl;
	os << "--use-alf" << std::endl
	   << "   Send ML features and flow info for ALF to the secondary output interface" << std::endl
	   << "   Default: " << std::boolalpha << useAlf() << std::endl;
	os << std::endl;

	os << "Args must be always passed separated by space:" << std::endl;
	os << "   OK:   -m model.pickle" << std::endl;
	os << "   FAIL: -mmodel.pickle" << std::endl;
}

} // namespace DeCrypto
