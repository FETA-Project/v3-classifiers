/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Transformer implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tunder/processing/transformer.hpp"

namespace TunDer {

using FlowFeatures = WIF::FlowFeatures;
using UnirecRecordView = NemeaPlusPlus::UnirecRecordView;
using UrTime = NemeaPlusPlus::UrTime;
using UrIpAddr = NemeaPlusPlus::IpAddress;
using WifIpAddr = WIF::IpAddress;

namespace {

uint64_t urTimeToUint64(const UrTime& time)
{
	return (uint64_t) ur_time_get_sec(time.time);
}

} // namespace

FlowFeatures Transformer::transform(const UnirecRecordView& record, bool reversed)
{
	m_features = FlowFeatures(WIF_ID::SIZE);

	if (reversed) {
		transformReversed(record);
	} else {
		transformNormally(record);
	}

	auto timeLast = record.getFieldAsType<UrTime>(m_unirecIDTable.TIME_LAST);
	m_features.set<uint64_t>(WIF_ID::TIME_LAST, urTimeToUint64(timeLast));

	m_features.set<uint16_t>(
		WIF_ID::OVPN_CONF_LEVEL,
		record.getFieldAsType<uint8_t>(m_unirecIDTable.OVPN_CONF_LEVEL));

	m_features.set<uint16_t>(
		WIF_ID::WG_CONF_LEVEL,
		record.getFieldAsType<uint8_t>(m_unirecIDTable.WG_CONF_LEVEL));

	m_features.set<uint16_t>(
		WIF_ID::SSA_CONF_LEVEL,
		record.getFieldAsType<uint8_t>(m_unirecIDTable.SSA_CONF_LEVEL));

	m_features.set<uint8_t>(
		WIF_ID::TOR_DETECTED,
		record.getFieldAsType<uint8_t>(m_unirecIDTable.TOR_DETECTED));

	return m_features;
}

void Transformer::transformNormally(const UnirecRecordView& record)
{
	auto srcIp = Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecIDTable.DST_IP));
	m_features.set<WifIpAddr>(WIF_ID::DST_IP, srcIp);

	auto dstIp = Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecIDTable.SRC_IP));
	m_features.set<WifIpAddr>(WIF_ID::SRC_IP, dstIp);

	auto srcPort = record.getFieldAsType<uint16_t>(m_unirecIDTable.DST_PORT);
	m_features.set<uint16_t>(WIF_ID::DST_PORT, srcPort);

	auto dstPort = record.getFieldAsType<uint16_t>(m_unirecIDTable.SRC_PORT);
	m_features.set<uint16_t>(WIF_ID::SRC_PORT, dstPort);
}

void Transformer::transformReversed(const UnirecRecordView& record)
{
	auto srcIp = Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecIDTable.DST_IP));
	m_features.set<WifIpAddr>(WIF_ID::SRC_IP, srcIp);

	auto dstIp = Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecIDTable.SRC_IP));
	m_features.set<WifIpAddr>(WIF_ID::DST_IP, dstIp);

	auto srcPort = record.getFieldAsType<uint16_t>(m_unirecIDTable.DST_PORT);
	m_features.set<uint16_t>(WIF_ID::SRC_PORT, srcPort);

	auto dstPort = record.getFieldAsType<uint16_t>(m_unirecIDTable.SRC_PORT);
	m_features.set<uint16_t>(WIF_ID::DST_PORT, dstPort);
}

} // namespace TunDer
