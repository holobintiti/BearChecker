// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title BearChecker
 * @notice On-chain toolkit for recording and querying market-cycle assessments. Submitters post phase, bear score, and risk level; keeper configures phase thresholds. Treasury receives optional fees. No off-chain data; all inputs are explicit.
 * @dev Treasury, keeper, and oracle addresses are set in the constructor and are immutable. ReentrancyGuard on all state-changing and payable paths.
 */

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/access/Ownable.sol";

contract BearChecker is ReentrancyGuard, Ownable {

    event CycleAssessmentSubmitted(
        uint256 indexed assessmentId,
        address indexed submitter,
        uint8 phaseId,
        uint256 bearScore,
        uint8 riskLevel,
        bytes32 metadataHash,
        uint256 atBlock
    );
    event PhaseThresholdSet(uint8 indexed phaseId, uint256 minScore, uint256 maxScore, uint256 atBlock);
    event BearScoreRecorded(uint256 indexed assessmentId, uint256 bearScore, uint8 riskLevel, uint256 atBlock);
    event TreasuryTopped(uint256 amountWei, address indexed from, uint256 atBlock);
    event TreasuryWithdrawn(address indexed to, uint256 amountWei, uint256 atBlock);
    event PauseToggled(bool paused);
    event KeeperUpdated(address indexed previous, address indexed current);
    event OracleUpdated(address indexed previous, address indexed current);
    event SubmissionFeeSet(uint256 previousWei, uint256 newWei);
    event CycleSnapshotRecorded(uint256 indexed snapshotIndex, uint8 phaseId, uint256 aggregateBearScore, uint256 atBlock);

    error BCH_ZeroAddress();
    error BCH_ZeroAmount();
    error BCH_Paused();
    error BCH_NotKeeper();
    error BCH_NotOracle();
    error BCH_InvalidPhase();
    error BCH_ScoreOutOfRange();
    error BCH_RiskLevelOutOfRange();
    error BCH_TransferFailed();
    error BCH_AssessmentNotFound();
    error BCH_InsufficientFee();
    error BCH_ThresholdInvalid();
    error BCH_MaxAssessmentsPerSubmitter();

    uint256 public constant BCH_SCORE_SCALE = 10000;
    uint256 public constant BCH_MAX_PHASES = 8;
    uint256 public constant BCH_MAX_RISK_LEVEL = 10;
    uint256 public constant BCH_MAX_ASSESSMENTS_PER_SUBMITTER = 256;
    uint256 public constant BCH_CYCLE_SEED = 0xBe4c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f;

    uint8 public constant BCH_PHASE_ACCUMULATION = 1;
    uint8 public constant BCH_PHASE_MARKUP = 2;
    uint8 public constant BCH_PHASE_DISTRIBUTION = 3;
    uint8 public constant BCH_PHASE_MARKDOWN = 4;

    address public immutable bchTreasury;
    address public immutable bchOracleRole;
    uint256 public immutable deployBlock;
    bytes32 public immutable chainSalt;

    address public bchKeeper;
    address public bchOracle;
    uint256 public submissionFeeWei;
    bool public bchPaused;
    uint256 public assessmentCounter;
    uint256 public treasuryBalance;

    struct CycleAssessment {
        address submitter;
        uint8 phaseId;
        uint256 bearScore;
        uint8 riskLevel;
        bytes32 metadataHash;
        uint256 atBlock;
    }

    struct PhaseThreshold {
        uint256 minScore;
        uint256 maxScore;
        bool configured;
    }

    mapping(uint256 => CycleAssessment) public assessments;
    mapping(address => uint256[]) public assessmentIdsBySubmitter;
    mapping(uint8 => PhaseThreshold) public phaseThresholds;
    mapping(uint8 => uint256) public assessmentCountByPhase;

    struct CycleSnapshot {
        uint8 phaseId;
        uint256 aggregateBearScore;
        uint256 atBlock;
    }
    CycleSnapshot[] private _cycleSnapshots;

    uint256[] private _allAssessmentIds;

    modifier whenNotPaused() {
        if (bchPaused) revert BCH_Paused();
        _;
    }

    modifier onlyKeeper() {
        if (msg.sender != bchKeeper && msg.sender != owner()) revert BCH_NotKeeper();
        _;
    }

    modifier onlyOracle() {
        if (msg.sender != bchOracle && msg.sender != owner()) revert BCH_NotOracle();
        _;
    }

    function _validatePhaseAndScore(uint8 phaseId, uint256 bearScore, uint8 riskLevel) internal pure {
        if (phaseId >= BCH_MAX_PHASES) revert BCH_InvalidPhase();
        if (bearScore > BCH_SCORE_SCALE) revert BCH_ScoreOutOfRange();
        if (riskLevel > BCH_MAX_RISK_LEVEL) revert BCH_RiskLevelOutOfRange();
    }

    constructor() {
        bchTreasury = address(0xBc1dE9f2A4c6e8F0a2B4c6D8e0F2a4B6c8D0e2);
        bchKeeper = address(0xCd2eF0a3B5c7D9e1F3a5B7c9D1e3F5a7B9c1D);
        bchOracleRole = address(0xDe3fA1b4C6d8E0f2A4b6C8d0E2f4A6b8C0d2E);
        bchOracle = address(0xEf4B2c5D7e9F1a3B5c7D9e1F3a5B7c9D1e3F);
        deployBlock = block.number;
        chainSalt = keccak256(abi.encodePacked("BearChecker_", block.chainid, block.timestamp, address(this)));
    }

    function setPaused(bool paused) external onlyOwner {
        bchPaused = paused;
        emit PauseToggled(paused);
    }

    function setKeeper(address newKeeper) external onlyOwner {
        if (newKeeper == address(0)) revert BCH_ZeroAddress();
        address prev = bchKeeper;
        bchKeeper = newKeeper;
        emit KeeperUpdated(prev, newKeeper);
    }

    function setOracle(address newOracle) external onlyOwner {
        if (newOracle == address(0)) revert BCH_ZeroAddress();
        address prev = bchOracle;
        bchOracle = newOracle;
        emit OracleUpdated(prev, newOracle);
    }

    function setSubmissionFeeWei(uint256 newFeeWei) external onlyOwner {
        uint256 prev = submissionFeeWei;
        submissionFeeWei = newFeeWei;
        emit SubmissionFeeSet(prev, newFeeWei);
    }

    /// @notice Set score bounds for a phase (keeper only). Used for cycle classification.
    function setPhaseThreshold(uint8 phaseId, uint256 minScore, uint256 maxScore) external onlyKeeper {
        if (phaseId >= BCH_MAX_PHASES) revert BCH_InvalidPhase();
        if (minScore > maxScore || maxScore > BCH_SCORE_SCALE) revert BCH_ThresholdInvalid();
        phaseThresholds[phaseId] = PhaseThreshold({ minScore: minScore, maxScore: maxScore, configured: true });
        emit PhaseThresholdSet(phaseId, minScore, maxScore, block.number);
    }

    /// @notice Submit a single market-cycle assessment. Optional fee sent to treasury.
    /// @param phaseId Phase index 0..BCH_MAX_PHASES-1 (e.g. BCH_PHASE_ACCUMULATION, BCH_PHASE_MARKDOWN).
    /// @param bearScore Bear score 0..BCH_SCORE_SCALE (10000 = max bearish).
    /// @param riskLevel Risk level 0..BCH_MAX_RISK_LEVEL.
    /// @param metadataHash Optional keccak256 of off-chain metadata.
    /// @return assessmentId Id of the created assessment.
    function submitAssessment(
        uint8 phaseId,
        uint256 bearScore,
        uint8 riskLevel,
        bytes32 metadataHash
    ) external payable whenNotPaused nonReentrant returns (uint256 assessmentId) {
        _validatePhaseAndScore(phaseId, bearScore, riskLevel);
        if (msg.value < submissionFeeWei) revert BCH_InsufficientFee();
        if (assessmentIdsBySubmitter[msg.sender].length >= BCH_MAX_ASSESSMENTS_PER_SUBMITTER) revert BCH_MaxAssessmentsPerSubmitter();

        if (msg.value > 0) {
            treasuryBalance += msg.value;
            emit TreasuryTopped(msg.value, msg.sender, block.number);
        }

        assessmentCounter++;
        assessmentId = assessmentCounter;
        assessments[assessmentId] = CycleAssessment({
            submitter: msg.sender,
            phaseId: phaseId,
            bearScore: bearScore,
            riskLevel: riskLevel,
            metadataHash: metadataHash,
            atBlock: block.number
        });
        assessmentIdsBySubmitter[msg.sender].push(assessmentId);
        assessmentCountByPhase[phaseId]++;
        _allAssessmentIds.push(assessmentId);

        emit CycleAssessmentSubmitted(assessmentId, msg.sender, phaseId, bearScore, riskLevel, metadataHash, block.number);
        emit BearScoreRecorded(assessmentId, bearScore, riskLevel, block.number);
        return assessmentId;
    }

    function submitAssessmentBatch(
        uint8[] calldata phaseIds,
        uint256[] calldata bearScores,
        uint8[] calldata riskLevels,
        bytes32[] calldata metadataHashes
    ) external payable whenNotPaused nonReentrant returns (uint256[] memory assessmentIds) {
        uint256 n = phaseIds.length;
        if (n == 0 || bearScores.length != n || riskLevels.length != n || metadataHashes.length != n) revert BCH_ThresholdInvalid();
        if (assessmentIdsBySubmitter[msg.sender].length + n > BCH_MAX_ASSESSMENTS_PER_SUBMITTER) revert BCH_MaxAssessmentsPerSubmitter();
        uint256 requiredFee = submissionFeeWei * n;
        if (msg.value < requiredFee) revert BCH_InsufficientFee();

        if (msg.value > 0) {
            treasuryBalance += msg.value;
            emit TreasuryTopped(msg.value, msg.sender, block.number);
        }

        assessmentIds = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            _validatePhaseAndScore(phaseIds[i], bearScores[i], riskLevels[i]);

            assessmentCounter++;
            uint256 aid = assessmentCounter;
            assessments[aid] = CycleAssessment({
                submitter: msg.sender,
                phaseId: phaseIds[i],
                bearScore: bearScores[i],
                riskLevel: riskLevels[i],
                metadataHash: metadataHashes[i],
                atBlock: block.number
            });
            assessmentIdsBySubmitter[msg.sender].push(aid);
            assessmentCountByPhase[phaseIds[i]]++;
            _allAssessmentIds.push(aid);
            assessmentIds[i] = aid;
            emit CycleAssessmentSubmitted(aid, msg.sender, phaseIds[i], bearScores[i], riskLevels[i], metadataHashes[i], block.number);
        }
        return assessmentIds;
    }

    /// @notice Withdraw treasury balance to bchTreasury. Callable by owner or bchTreasury.
    function recordCycleSnapshot(uint8 phaseId, uint256 aggregateBearScore) external onlyOracle whenNotPaused {
        if (phaseId >= BCH_MAX_PHASES) revert BCH_InvalidPhase();
        if (aggregateBearScore > BCH_SCORE_SCALE) revert BCH_ScoreOutOfRange();
        _cycleSnapshots.push(CycleSnapshot({
            phaseId: phaseId,
            aggregateBearScore: aggregateBearScore,
            atBlock: block.number
        }));
        emit CycleSnapshotRecorded(_cycleSnapshots.length - 1, phaseId, aggregateBearScore, block.number);
    }

    function withdrawTreasury() external nonReentrant {
        if (msg.sender != owner() && msg.sender != bchTreasury) revert BCH_ZeroAddress();
        uint256 amount = treasuryBalance;
        if (amount == 0) revert BCH_ZeroAmount();
        treasuryBalance = 0;
        (bool sent,) = bchTreasury.call{value: amount}("");
        if (!sent) revert BCH_TransferFailed();
        emit TreasuryWithdrawn(bchTreasury, amount, block.number);
    }

    /// @param assessmentId Assessment id.
    /// @return submitter Submitter address.
    /// @return phaseId Phase index.
    /// @return bearScore Bear score 0..BCH_SCORE_SCALE.
    /// @return riskLevel Risk level 0..BCH_MAX_RISK_LEVEL.
    /// @return metadataHash Optional metadata hash.
    /// @return atBlock Block when submitted.
    function getAssessment(uint256 assessmentId) external view returns (
        address submitter,
        uint8 phaseId,
        uint256 bearScore,
        uint8 riskLevel,
        bytes32 metadataHash,
        uint256 atBlock
    ) {
        CycleAssessment storage a = assessments[assessmentId];
        if (a.atBlock == 0) revert BCH_AssessmentNotFound();
        return (a.submitter, a.phaseId, a.bearScore, a.riskLevel, a.metadataHash, a.atBlock);
    }

    function getAssessmentIdsBySubmitter(address submitter) external view returns (uint256[] memory) {
        return assessmentIdsBySubmitter[submitter];
    }

    function getAllAssessmentIds() external view returns (uint256[] memory) {
        return _allAssessmentIds;
    }

    /// @param phaseId Phase index 0..BCH_MAX_PHASES-1.
    /// @return minScore Minimum score for this phase (configured by keeper).
    /// @return maxScore Maximum score for this phase.
    /// @return configured Whether threshold was set.
    function getPhaseThreshold(uint8 phaseId) external view returns (uint256 minScore, uint256 maxScore, bool configured) {
        PhaseThreshold storage pt = phaseThresholds[phaseId];
        return (pt.minScore, pt.maxScore, pt.configured);
    }

    function getConfigSnapshot() external view returns (
        address bchTreasury_,
        address bchKeeper_,
        address bchOracle_,
        uint256 deployBlock_,
        uint256 submissionFeeWei_,
        uint256 assessmentCounter_,
        uint256 treasuryBalance_,
        bool bchPaused_
    ) {
        return (
            bchTreasury,
            bchKeeper,
            bchOracle,
            deployBlock,
            submissionFeeWei,
            assessmentCounter,
            treasuryBalance,
            bchPaused
        );
    }

    function getAssessmentsBatch(uint256[] calldata assessmentIds) external view returns (
        address[] memory submitters,
        uint8[] memory phaseIds,
        uint256[] memory bearScores,
        uint8[] memory riskLevels,
        bytes32[] memory metadataHashes,
        uint256[] memory atBlocks
    ) {
        uint256 n = assessmentIds.length;
        submitters = new address[](n);
        phaseIds = new uint8[](n);
        bearScores = new uint256[](n);
        riskLevels = new uint8[](n);
        metadataHashes = new bytes32[](n);
        atBlocks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            CycleAssessment storage a = assessments[assessmentIds[i]];
            submitters[i] = a.submitter;
            phaseIds[i] = a.phaseId;
            bearScores[i] = a.bearScore;
            riskLevels[i] = a.riskLevel;
            metadataHashes[i] = a.metadataHash;
            atBlocks[i] = a.atBlock;
        }
    }

    function getLatestAssessments(uint256 count) external view returns (
        uint256[] memory ids,
        address[] memory submitters,
        uint8[] memory phaseIds,
        uint256[] memory bearScores,
        uint8[] memory riskLevels
    ) {
        uint256 len = _allAssessmentIds.length;
        if (len == 0) return (new uint256[](0), new address[](0), new uint8[](0), new uint256[](0), new uint8[](0));
        if (count > len) count = len;
        ids = new uint256[](count);
        submitters = new address[](count);
        phaseIds = new uint8[](count);
        bearScores = new uint256[](count);
        riskLevels = new uint8[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 aid = _allAssessmentIds[len - 1 - i];
            CycleAssessment storage a = assessments[aid];
            ids[i] = aid;
            submitters[i] = a.submitter;
            phaseIds[i] = a.phaseId;
            bearScores[i] = a.bearScore;
            riskLevels[i] = a.riskLevel;
        }
    }

    function getAverageBearScore() external view returns (uint256 average, uint256 count) {
        count = _allAssessmentIds.length;
        if (count == 0) return (0, 0);
        uint256 sum = 0;
        for (uint256 i = 0; i < count; i++) {
            sum += assessments[_allAssessmentIds[i]].bearScore;
        }
        average = sum / count;
        return (average, count);
    }

    function getAverageBearScoreByPhase(uint8 phaseId) external view returns (uint256 average, uint256 count) {
        if (phaseId >= BCH_MAX_PHASES) return (0, 0);
        count = 0;
        uint256 sum = 0;
        for (uint256 i = 0; i < _allAssessmentIds.length; i++) {
            CycleAssessment storage a = assessments[_allAssessmentIds[i]];
            if (a.phaseId == phaseId) {
                sum += a.bearScore;
                count++;
            }
        }
        if (count == 0) return (0, 0);
        average = sum / count;
        return (average, count);
    }

    function getSubmitterStats(address submitter) external view returns (uint256 count, uint256[] memory ids) {
        ids = assessmentIdsBySubmitter[submitter];
        count = ids.length;
        return (count, ids);
    }

    function getPhaseStats(uint8 phaseId) external view returns (uint256 count, uint256 minScore, uint256 maxScore, bool configured) {
        if (phaseId >= BCH_MAX_PHASES) return (0, 0, 0, false);
        PhaseThreshold storage pt = phaseThresholds[phaseId];
        return (assessmentCountByPhase[phaseId], pt.minScore, pt.maxScore, pt.configured);
    }

    function getAssessmentCountByPhaseBatch(uint8[] calldata phaseIds) external view returns (uint256[] memory counts) {
        uint256 n = phaseIds.length;
        counts = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            if (phaseIds[i] < BCH_MAX_PHASES) counts[i] = assessmentCountByPhase[phaseIds[i]];
        }
    }

    function getAssessmentsPaginated(uint256 offset, uint256 limit) external view returns (uint256[] memory ids) {
        uint256 len = _allAssessmentIds.length;
        if (offset >= len) return new uint256[](0);
        uint256 end = offset + limit;
        if (end > len) end = len;
        uint256 n = end - offset;
        ids = new uint256[](n);
        for (uint256 i = 0; i < n; i++) ids[i] = _allAssessmentIds[offset + i];
        return ids;
    }
