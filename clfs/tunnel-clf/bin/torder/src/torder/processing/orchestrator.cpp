/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Orchestrator interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "torder/processing/orchestrator.hpp"

#include <iostream>

namespace TorDer {

Orchestrator::Orchestrator(const Config& config, OutputInterface& outputIfc)
	: m_unirecTable()
	, m_transformer(m_unirecTable)
	, m_outIfc(outputIfc)
	, m_detector(config.torRelaysFilePath(), config.tickIntervalInSeconds())
{
}

void Orchestrator::onTemplateChange(const std::string& unirecTemplate)
{
	m_outIfc.changeTemplate(unirecTemplate);
	m_unirecTable.update();
}

void Orchestrator::onFlowReceived(const UnirecRecordView& record)
{
	// Exxtract needed features for detection and pass it to the detector
	auto flowFeatures = m_transformer.transform(record);
	m_detector.update(flowFeatures);

	// Prepare a copy of received unirec record and copy fields from the original one
	auto& outRecord = m_outIfc.getUnirecRecord();
	outRecord.copyFieldsFrom(record);

	// Fill results of the detection
	outRecord.setFieldFromType<uint8_t>(m_detector.result(), m_unirecTable.TOR_DETECTED);
	outRecord.setFieldFromType<int8_t>(m_detector.direction(), m_unirecTable.TOR_DIRECTION);

	// Send record to the output interface
	m_outIfc.send(outRecord);
}

void Orchestrator::onEnd() {}

} // namespace TorDer
