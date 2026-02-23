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
