/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Transformer interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "tunder/settings/unirecIDTable.hpp"
#include "tunder/settings/wifTemplate.hpp"
#include "tunder/utils/ipConvertor.hpp"
#include <unirec++/unirec.hpp>
#include <unirec/unirec.h>
#include <wif/flowFeatures.hpp>

namespace TunDer {

class Transformer {
	using UnirecRecordView = NemeaPlusPlus::UnirecRecordView;
	using FlowFeatures = WIF::FlowFeatures;
	using UrIpAddr = NemeaPlusPlus::IpAddress;

public:
	Transformer(UnirecIDTable& unirecIDTable)
		: m_unirecIDTable(unirecIDTable)
		, m_features(0)
	{
	}

	WIF::IpAddress extractSrcIp(const UnirecRecordView& record) const
	{
		return Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecIDTable.SRC_IP));
	}

	WIF::IpAddress extractDstIp(const UnirecRecordView& record) const
	{
		return Utils::toWifIp(record.getFieldAsType<UrIpAddr>(m_unirecIDTable.DST_IP));
	}

	FlowFeatures transform(const UnirecRecordView& record, bool reversed);

private:
	void transformNormally(const UnirecRecordView& record);
	void transformReversed(const UnirecRecordView& record);

	UnirecIDTable& m_unirecIDTable;
	FlowFeatures m_features;
};

} // namespace TunDer
