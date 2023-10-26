/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Transformer interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "torder/settings/unirecTable.hpp"
#include "torder/settings/wifTable.hpp"
#include "torder/utils/ipConvertor.hpp"
#include <unirec++/unirec.hpp>
#include <unirec/unirec.h>
#include <wif/flowFeatures.hpp>

#include <iostream>

namespace TorDer {

class Transformer {
	using UnirecRecordView = NemeaPlusPlus::UnirecRecordView;
	using FlowFeatures = WIF::FlowFeatures;
	using UrIpAddr = NemeaPlusPlus::IpAddress;
	using WifIpAddr = WIF::IpAddress;

public:
	Transformer(UnirecTable& unirecTable)
		: m_unirecTable(unirecTable)
		, m_features(0)
	{
	}

	FlowFeatures transform(const UnirecRecordView& record)
	{
		m_features = FlowFeatures(WIF_ID::SIZE);

		auto srcIp = Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecTable.SRC_IP));
		m_features.set<WifIpAddr>(WIF_ID::SRC_IP, srcIp);

		auto dstIp = Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecTable.DST_IP));
		m_features.set<WifIpAddr>(WIF_ID::DST_IP, dstIp);

		return m_features;
	}

private:
	UnirecTable& m_unirecTable;
	FlowFeatures m_features;
};

} // namespace TorDer
