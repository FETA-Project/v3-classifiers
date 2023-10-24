/**
 * @file
 * @author Richard Plny <plnyrich@fit.cvut.cz>
 * @brief Main loop implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "decrypto/processor/processor.hpp"

using namespace NemeaPlusPlus;
using namespace WIF;

#include <iostream>
#include <unirec/unirec.h>

namespace DeCrypto {

namespace {

inline std::vector<FlowFeatures> createBuffer(const Config& config)
{
	return std::vector<FlowFeatures>(config.bufferSize(), FlowFeatures(FLOW_FEATURES_SIZE));
}

inline void prepareInputIfc(UnirecInputInterface& inputIfc, bool debug)
{
	const auto templateDefinition = Templates::getInputTemplate(debug);
	inputIfc.setRequieredFormat(templateDefinition);
}

inline void prepareOutputIfc(UnirecOutputInterface& outputIfc, bool debug)
{
	const auto templateDefinition = Templates::getOutputTemplate(debug);
	outputIfc.changeTemplate(templateDefinition);
}

inline std::pair<double, double> calculateRecvSentRatios(UnirecArray<int8_t>& directions)
{
	uint64_t sentSum = 0;
	for (unsigned directionId = 0; directionId < directions.size(); ++directionId) {
		if (directions[directionId] == SENT_DIRECTION) {
			++sentSum;
		}
	}
	double sentRatio = directions.size() > 0 ? (double) sentSum / directions.size() : 0;
	double recvRatio = 1.0 - sentRatio;
	return {sentRatio, recvRatio};
}

inline double calculateAveragePacketInterval(UnirecArray<UrTime>& times)
{
	double intervalSum = 0;
	for (unsigned timeId = 1; timeId < times.size(); ++timeId) {
		auto t1 = ur_time_get_sec(times[timeId].time);
		auto t2 = ur_time_get_sec(times[timeId - 1].time);
		intervalSum += t1 - t2;
	}
	return (times.size() - 1) > 0 ? intervalSum / (times.size() - 1) : 0.0;
}

inline double calculateOverallDuration(UrTime timeFirst, UrTime timeLast)
{
	auto first = ur_time_get_sec(timeFirst.time);
	auto last = ur_time_get_sec(timeLast.time);
	return last - first;
}

inline std::tuple<double, double, double>
calculateSizeStatistics(UnirecArray<uint16_t>& lengths, UnirecArray<int8_t>& directions)
{
	uint64_t lenSum = 0;
	uint16_t minPktLen = lengths[0];
	uint64_t sumSent = 0;
	uint64_t sumRecv = 0;
	for (unsigned lenId = 0; lenId < lengths.size(); ++lenId) {
		lenSum += lengths[lenId];
		if (lengths[lenId] < minPktLen) {
			minPktLen = lengths[lenId];
		}
		if (directions[lenId] == SENT_DIRECTION) {
			sumSent += lengths[lenId];
		} else {
			sumRecv += lengths[lenId];
		}
	}
	double avgPktSize = lengths.size() > 0 ? (double) lenSum / lengths.size() : 0;
	double dataSymmetry = sumRecv > 0 ? (double) sumSent / sumRecv : 0;
	return {avgPktSize, minPktLen, dataSymmetry};
}

inline double calculatePushRatio(UnirecArray<uint8_t>& flags)
{
	uint64_t pushSum = 0;
	for (unsigned flagId = 0; flagId < flags.size(); ++flagId) {
		pushSum += ((uint8_t) (flags[flagId])) & 8;
	}
	return flags.size() > 0 ? (double) (pushSum / 8) / flags.size() : 0;
}

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

} // namespace

Processor::Processor(const Config& config, UnirecOutputInterface& reporterIfc)
	: m_config(config)
	, m_evaluator(config.debug())
	, m_metaClassifier(m_config, m_perfTracker, reporterIfc)
{
	m_flowBuffer = createBuffer(m_config);
}

void Processor::mainLoop(UnirecInputInterface& inputIfc, UnirecOutputInterface& outputIfc)
{
	prepareInputIfc(inputIfc, m_config.debug());
	prepareOutputIfc(outputIfc, m_config.debug());

	m_metaClassifier.setSources(m_translationTable.wifIds());

	while (true) {
		try {
			std::optional<UnirecRecordView> unirecRecord = inputIfc.receive();
			if (!unirecRecord) {
				break;
			}
			if (prefilter(*unirecRecord)) {
				continue;
			}

			extractFeaturesToBuffer(m_flowBuffer[m_nextFlowId++], *unirecRecord);

			if (m_nextFlowId == m_config.bufferSize()) {
				doDetection(m_flowBuffer, outputIfc);
				m_nextFlowId = 0;
			}

		} catch (EoFException&) {
			std::cout << "EoF" << std::endl;
			break;
		} catch (FormatChangeException&) {
			inputIfc.changeTemplate();
			m_translationTable.update();
		}
	}

	if (m_nextFlowId != 0) {
		std::vector<FlowFeatures>::const_iterator first = m_flowBuffer.begin();
		std::vector<FlowFeatures>::const_iterator last = m_flowBuffer.begin() + m_nextFlowId;
		doDetection(std::vector<FlowFeatures>(first, last), outputIfc);
	}

	outputIfc.sendFlush();
	m_evaluator.dumpAll(std::cout);
	m_perfTracker.dumpAll(std::cout);
}

// True if flow should be dropped, False if continue processing
bool Processor::prefilter(const NemeaPlusPlus::UnirecRecordView& flow) const
{
	if (flow.getFieldAsType<uint32_t>(m_translationTable.unirecIds().PACKETS) < 8) {
		return true;
	}
	if (flow.getFieldAsType<uint32_t>(m_translationTable.unirecIds().PACKETS_REV) < 8) {
		return true;
	}
	return false;
}

void Processor::doDetection(
	const std::vector<FlowFeatures>& buffer,
	UnirecOutputInterface& outputIfc)
{
	std::vector<std::vector<double>> results = m_metaClassifier.classify(buffer);

	for (unsigned flowId = 0; flowId < results.size(); ++flowId) {
		bool prediction = false;
		auto detectorId = Evaluator::UNKNOWN;
		std::string explanation = "";

		auto detectionResult = results[flowId];
		auto tlsSni = buffer[flowId].get<std::string>(m_translationTable.wifIds().TLS_SNI);
		if (detectionResult[STRATUM_RESULT_ID] == 1) {
			prediction = true;
			detectorId = Evaluator::STRATUM_DETECTOR;
			explanation = "STRATUM";
		} else if (tlsSni.size() > 0) {
			prediction = detectionResult[DST_RESULT_ID] > m_config.dstThreshold();
			detectorId = Evaluator::DST_COMBINATION;
			explanation = "DST";
		} else {
			prediction = detectionResult[ML_PROBA_ID] >= m_config.mlThreshold();
			detectorId = Evaluator::ML_CLASSIFIER;
			explanation = "ML";
		}

		if (m_config.debug()) {
			const auto label = buffer[flowId].get<std::string>(m_translationTable.wifIds().LABEL);
			m_evaluator.addResult(detectorId, prediction, label);
		} else {
			m_evaluator.addResult(detectorId, prediction);
		}

		if (!prediction && !m_config.debug()) {
			continue;
		}

		sendToOutput(outputIfc, m_flowBuffer[flowId], prediction, explanation);
	}
}

void Processor::sendToOutput(
	UnirecOutputInterface& outputIfc,
	const FlowFeatures& flow,
	bool prediction,
	const std::string& predictionPath)
{
	const auto& uIds = m_translationTable.unirecIds();
	const auto& wIds = m_translationTable.wifIds();
	auto& record = outputIfc.getUnirecRecord();
	auto detectionTime = UrTime::now();

	// IPs, Ports, Protocol
	record.setFieldFromType<NemeaPlusPlus::IpAddress>(
		toNemeaIp(flow.get<WIF::IpAddress>(wIds.SRC_IP)),
		uIds.SRC_IP);
	record.setFieldFromType<NemeaPlusPlus::IpAddress>(
		toNemeaIp(flow.get<WIF::IpAddress>(wIds.DST_IP)),
		uIds.DST_IP);

	record.setFieldFromType<uint16_t>(flow.get<uint16_t>(wIds.SRC_PORT), uIds.SRC_PORT);
	record.setFieldFromType<uint16_t>(flow.get<uint16_t>(wIds.DST_PORT), uIds.DST_PORT);
	record.setFieldFromType<uint8_t>(flow.get<uint8_t>(wIds.PROTOCOL), uIds.PROTOCOL);

	record.setFieldFromType<uint32_t>(flow.get<double>(wIds.PACKETS), uIds.PACKETS);
	record.setFieldFromType<uint32_t>(flow.get<double>(wIds.PACKETS_REV), uIds.PACKETS_REV);
	record.setFieldFromType<uint64_t>(flow.get<double>(wIds.BYTES), uIds.BYTES);
	record.setFieldFromType<uint64_t>(flow.get<double>(wIds.BYTES_REV), uIds.BYTES_REV);

	auto timeFirst = flow.get<uint64_t>(wIds.TIME_FIRST);
	auto timeLast = flow.get<uint64_t>(wIds.TIME_LAST);
	record.setFieldFromType<UrTime>({static_cast<ur_time_t>(timeFirst)}, uIds.TIME_FIRST);
	record.setFieldFromType<UrTime>({static_cast<ur_time_t>(timeLast)}, uIds.TIME_LAST);
	record.setFieldFromType<UrTime>(detectionTime, uIds.DETECT_TIME);

	record.setFieldFromType<std::string>(flow.get<std::string>(wIds.TLS_SNI), uIds.TLS_SNI);
	record.setFieldFromType<std::string>(predictionPath, uIds.EXPLANATION);

	record.setFieldFromType<uint8_t>(prediction, uIds.PREDICTION);

	outputIfc.send(record);
}

void Processor::extractFeaturesToBuffer(FlowFeatures& target, const UnirecRecordView& flow) const
{
	const auto& uIds = m_translationTable.unirecIds();
	const auto& wIds = m_translationTable.wifIds();

	// IPs, Ports, Protocol
	target.set<WIF::IpAddress>(
		wIds.SRC_IP,
		toWifIp(flow.getFieldAsType<NemeaPlusPlus::IpAddress>(uIds.SRC_IP)));
	target.set<WIF::IpAddress>(
		wIds.DST_IP,
		toWifIp(flow.getFieldAsType<NemeaPlusPlus::IpAddress>(uIds.DST_IP)));

	target.set<uint16_t>(wIds.SRC_PORT, flow.getFieldAsType<uint16_t>(uIds.SRC_PORT));
	target.set<uint16_t>(wIds.DST_PORT, flow.getFieldAsType<uint16_t>(uIds.DST_PORT));
	target.set<uint8_t>(wIds.PROTOCOL, flow.getFieldAsType<uint8_t>(uIds.PROTOCOL));

	// Basic flow
	target.set<double>(wIds.PACKETS, flow.getFieldAsType<uint32_t>(uIds.PACKETS));
	target.set<double>(wIds.PACKETS_REV, flow.getFieldAsType<uint32_t>(uIds.PACKETS_REV));
	target.set<double>(wIds.BYTES, flow.getFieldAsType<uint64_t>(uIds.BYTES));
	target.set<double>(wIds.BYTES_REV, flow.getFieldAsType<uint64_t>(uIds.BYTES_REV));

	auto timeFirst = flow.getFieldAsType<UrTime>(uIds.TIME_FIRST);
	auto timeLast = flow.getFieldAsType<UrTime>(uIds.TIME_LAST);
	target.set<uint64_t>(wIds.TIME_FIRST, static_cast<uint64_t>(timeFirst.time));
	target.set<uint64_t>(wIds.TIME_LAST, static_cast<uint64_t>(timeLast.time));

	target.set<uint8_t>(wIds.TCP_FLAGS, flow.getFieldAsType<uint8_t>(uIds.TCP_FLAGS));
	target.set<uint8_t>(wIds.TCP_FLAGS_REV, flow.getFieldAsType<uint8_t>(uIds.TCP_FLAGS_REV));

	// IDP Contents
	auto idpContent = flow.getFieldAsUnirecArray<std::byte>(uIds.IDP_CONTENT);
	std::string idpContentStr((const char*) idpContent.begin().data(), idpContent.size());
	target.set<std::string>(wIds.IDP_CONTENT, idpContentStr);

	auto idpContentRev = flow.getFieldAsUnirecArray<std::byte>(uIds.IDP_CONTENT_REV);
	std::string idpContentRevStr((const char*) idpContentRev.begin().data(), idpContentRev.size());
	target.set<std::string>(wIds.IDP_CONTENT_REV, idpContentRevStr);

	// TLS SNI
	target.set<std::string>(wIds.TLS_SNI, flow.getFieldAsType<std::string>(uIds.TLS_SNI));

	// If debug mode, then LABEL
	if (m_config.debug()) {
		target.set<std::string>(wIds.LABEL, flow.getFieldAsType<std::string>(uIds.LABEL));
	}

	// Calculate features for ML
	auto ppiPktDirections = flow.getFieldAsUnirecArray<int8_t>(uIds.PPI_PKT_DIRECTIONS);
	auto [sent, recv] = calculateRecvSentRatios(ppiPktDirections);
	target.set<double>(wIds.F_SENT, sent);
	target.set<double>(wIds.F_RECV, recv);

	auto ppiPktTimes = flow.getFieldAsUnirecArray<UrTime>(uIds.PPI_PKT_TIMES);
	auto avgPktInterval = calculateAveragePacketInterval(ppiPktTimes);
	target.set<double>(wIds.F_AVG_PKT_INTERVAL, avgPktInterval);

	auto overallDuration = calculateOverallDuration(timeFirst, timeLast);
	target.set<double>(wIds.F_OVERALL_DURATION, overallDuration);

	auto ppiPktLengths = flow.getFieldAsUnirecArray<uint16_t>(uIds.PPI_PKT_LENGTHS);
	auto [avgPktSize, minPktLen, dataSymmetry]
		= calculateSizeStatistics(ppiPktLengths, ppiPktDirections);
	target.set<double>(wIds.F_AVG_PKT_SIZE, avgPktSize);
	target.set<double>(wIds.F_MIN_PKT_LEN, minPktLen);
	target.set<double>(wIds.F_DATA_SYMMETRY, dataSymmetry);

	auto ppiPktFlags = flow.getFieldAsUnirecArray<uint8_t>(uIds.PPI_PKT_FLAGS);
	auto pushRatio = calculatePushRatio(ppiPktFlags);
	target.set<double>(wIds.F_PUSH_RATIO, pushRatio);
}

} // namespace DeCrypto
