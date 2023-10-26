/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief IP Convertor
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <unirec++/ipAddress.hpp>
#include <wif/ip/ipAddress.hpp>

namespace TorDer::Utils {

inline WIF::IpAddress toWifIp(const NemeaPlusPlus::IpAddress& ip)
{
	return WIF::IpAddress(ip.ip.bytes, WIF::IpAddress::IpVersion::VERSION_6, true);
}

inline NemeaPlusPlus::IpAddress toNemeaIp(const WIF::IpAddress& ip)
{
	NemeaPlusPlus::IpAddress newIp;
	std::memcpy(&newIp.ip.bytes, ip.data(), 16);
	return newIp;
}

} // namespace TorDer::Utils
