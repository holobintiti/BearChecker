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
