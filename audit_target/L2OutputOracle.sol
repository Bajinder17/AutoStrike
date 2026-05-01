// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { ISemver } from "src/universal/ISemver.sol";
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { Types } from "src/libraries/Types.sol";
import { ISP1Verifier } from "@sp1-contracts/ISP1Verifier.sol";
import { SuperchainConfig } from "src/L1/SuperchainConfig.sol";

/// @custom:proxied
/// @title L2OutputOracle
/// @notice The L2OutputOracle contains an array of L2 state outputs, where each output is a
///         commitment to the state of the L2 chain. Other contracts like the OptimismPortal use
///         these outputs to verify information about the state of L2. The outputs posted to this contract
///         are proved to be valid with `op-succinct`.
contract L2OutputOracle is Initializable, Ownable2StepUpgradeable, ISemver {
    /// @notice Parameters to initialize the L2OutputOracle contract.
    struct InitParams {
        uint256 l2ChainId;
        uint256 l2BlockTime;
        uint256 startingBlockNumber;
        uint256 startingTimestamp;
        address proposer;
        address challenger;
        address verifierV3;
        uint256 finalizationPeriodSeconds;
        bytes32 aggregationVkey;
        bytes32 rangeVkeyCommitment;
        bytes32 rollupConfigHash;
        address owner;
        address superchainConfig;
        uint256 timeLimitOutputRootSubmissionSeconds;
    }

    /// @dev Address of the EIP-2935 history storage contract.
    address internal constant HISTORY_STORAGE_ADDRESS = 0x0000F90827F1C53a10cb7A02335B175320002935;

    /// @notice The number of the first L2 block recorded in this contract.
    uint256 public startingBlockNumber;

    /// @notice The timestamp of the first L2 block recorded in this contract.
    uint256 public startingTimestamp;

    /// @notice An array of L2 output proposals.
    Types.OutputProposal[] internal l2Outputs;

    /// @notice The minimum time (in seconds) that must elapse before a withdrawal can be finalized.
    /// @custom:network-specific
    uint256 public finalizationPeriodSeconds;

    uint256 spacer_4_0_32;

    /// @notice The time between L2 blocks in seconds. Once set, this value MUST NOT be modified.
    /// @custom:network-specific
    uint256 public l2BlockTime;

    /// @notice The address of the challenger. Can be updated via upgrade.
    /// @custom:network-specific
    address public challenger;

    uint256 spacer_7_0_32;
    /// @notice The address of the proposer. Can be updated via upgrade.
    /// @custom:network-specific
    address public proposer;

    /// @notice Gaps for deprecated members
    /// @custom:network-specific
    uint256 spacer_9_0_32;

    /// @notice The chain ID of the L2
    uint256 public l2ChainId;

    uint256 spacer_11_0_32;

    uint256 spacer_12_0_32;

    uint256 spacer_13_0_32;

    /// @notice Maximum amount of time that can pass without receiving new L2 output proposals.
    uint256 public timeLimitOutputRootSubmissionSeconds;

    /// @notice SuperchainConfig contract address used for fetching pause time
    SuperchainConfig public superchainConfig;

    /// @notice The verification key of the aggregation SP1 program.
    bytes32 public aggregationVkey;

    /// @notice The 32 byte commitment to the BabyBear representation of the verification key of the range SP1 program.
    /// Specifically,
    /// this verification is the output of converting the [u32; 8] range BabyBear verification key to a [u8; 32] array.
    bytes32 public rangeVkeyCommitment;

    /// @notice The deployed SP1Verifier contract to verify proofs.
    address public verifierV3;

    /// @notice The hash of the chain's rollup config, which ensures the proofs submitted are for the correct chain.
    bytes32 public rollupConfigHash;

    /// @notice A trusted mapping of block numbers to block hashes.
    mapping(uint256 => bytes32) public historicBlockHashes;

    uint256 spacer_21_0_32;

    /// @notice Extended data for output proposals.
    /// @dev Maps output index to extended proposal data. This mapping can be extended with new fields
    ///      in OutputProposalExtension without breaking backwards compatibility. For outputs created
    ///      before fields were added, those field values will be zero/address(0).
    mapping(uint256 => Types.OutputProposalExtension) internal l2OutputsExtension; 

    ////////////////////////////////////////////////////////////
    //                         Events                         //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted when a v2 output is proposed. This is a legacy event kept for abi generation.
    /// @param poseidonStateRoot The output root.
    /// @param l2OutputIndex The index of the output in the l2Outputs/l2OutputsEx array.
    /// @param batchIndex The batch index of the proof.
    /// @param batchHash  The batch hash of the proof.
    /// @custom:legacy
    event OutputProposedV2(
        bytes32 indexed poseidonStateRoot, uint256 indexed l2OutputIndex, uint256 batchIndex, bytes32 batchHash
    );

    /// @notice Emitted when an output is proposed.
    /// @param outputRoot    The output root.
    /// @param l2OutputIndex The index of the output in the l2Outputs array.
    /// @param l2BlockNumber The L2 block number of the output root.
    /// @param l1Timestamp   The L1 timestamp when proposed.
    event OutputProposed(
        bytes32 indexed outputRoot, uint256 indexed l2OutputIndex, uint256 indexed l2BlockNumber, uint256 l1Timestamp
    );

    /// @notice Emitted when outputs are deleted.
    /// @param prevNextOutputIndex Next L2 output index before the deletion.
    /// @param newNextOutputIndex  Next L2 output index after the deletion.
    event OutputsDeleted(uint256 indexed prevNextOutputIndex, uint256 indexed newNextOutputIndex);

    /// @notice Emitted when the aggregation verification key is updated.
    /// @param oldAggregationVkey The old aggregation verification key.
    /// @param newAggregationVkey The new aggregation verification key.
    event AggregationVkeyUpdated(bytes32 indexed oldAggregationVkey, bytes32 indexed newAggregationVkey);

    /// @notice Emitted when the range verification key commitment is updated.
    /// @param oldRangeVkeyCommitment The old range verification key commitment.
    /// @param newRangeVkeyCommitment The new range verification key commitment.
    event RangeVkeyCommitmentUpdated(bytes32 indexed oldRangeVkeyCommitment, bytes32 indexed newRangeVkeyCommitment);

    /// @notice Emitted when the verifier address is updated.
    /// @param oldVerifier The old verifier address.
    /// @param newVerifier The new verifier address.
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted when the rollup config hash is updated.
    /// @param oldRollupConfigHash The old rollup config hash.
    /// @param newRollupConfigHash The new rollup config hash.
    event RollupConfigHashUpdated(bytes32 indexed oldRollupConfigHash, bytes32 indexed newRollupConfigHash);

    /// @notice Emitted when a proposer address is added.
    /// @param proposer The proposer address.
    /// @param added Whether the proposer was added or removed.
    event ProposerUpdated(address indexed proposer, bool added);

    ////////////////////////////////////////////////////////////
    //                         Errors                         //
    ////////////////////////////////////////////////////////////

    /// @notice The L1 block hash is not available. If the block hash requested is not in the last 256 blocks,
    ///         it is not available.
    error L1BlockHashNotAvailable();

    /// @notice The L1 block hash is not checkpointed.
    error L1BlockHashNotCheckpointed();

    /// @notice The bootstrap was already performed.
    error BootstrapAlreadyPerformed();

    /// @notice The output for this block has not been proposed yet
    error BlockNotProposed();

    /// @notice Semantic version.
    /// @custom:semver 3.1.1
    string public constant version = "3.1.1";

    /// @notice The version of the initializer on the contract. Used for managing upgrades.
    uint8 public constant initializerVersion = 2;

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    /// @notice Constructs the L2OutputOracle contract. Disables initializers.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializer.
    /// @param _initParams The initialization parameters for the contract.
    function initialize(InitParams memory _initParams) public reinitializer(initializerVersion) {
        require(_initParams.l2BlockTime > 0, "L2OutputOracle: L2 block time must be greater than 0");
        require(
            _initParams.startingTimestamp <= block.timestamp,
            "L2OutputOracle: starting L2 timestamp must be less than current time"
        );

        l2BlockTime = _initParams.l2BlockTime;

        // For proof verification to work, there must be an initial output.
        // Disregard the _startingBlockNumber and _startingTimestamp parameters during upgrades, as they're already set.
        if (l2Outputs.length == 0) {
            startingBlockNumber = _initParams.startingBlockNumber;
            startingTimestamp = _initParams.startingTimestamp;
        }

        proposer = _initParams.proposer;
        challenger = _initParams.challenger;
        finalizationPeriodSeconds = _initParams.finalizationPeriodSeconds;
        l2ChainId = _initParams.l2ChainId;
        timeLimitOutputRootSubmissionSeconds = _initParams.timeLimitOutputRootSubmissionSeconds;
        superchainConfig = SuperchainConfig(_initParams.superchainConfig);

        // OP Succinct initialization parameters.
        aggregationVkey = _initParams.aggregationVkey;
        rangeVkeyCommitment = _initParams.rangeVkeyCommitment;
        verifierV3 = _initParams.verifierV3;
        rollupConfigHash = _initParams.rollupConfigHash;
        _transferOwnership(_initParams.owner);
    }

    /// @notice Getter for the l2BlockTime.
    ///         Public getter is legacy and will be removed in the future. Use `l2BlockTime` instead.
    /// @return L2 block time.
    /// @custom:legacy
    function L2_BLOCK_TIME() external view returns (uint256) {
        return l2BlockTime;
    }

    /// @notice Getter for the challenger address.
    ///         Public getter is legacy and will be removed in the future. Use `challenger` instead.
    /// @return Address of the challenger.
    /// @custom:legacy
    function CHALLENGER() external view returns (address) {
        return challenger;
    }

    /// @notice Getter for the proposer address.
    ///         Public getter is legacy and will be removed in the future. Use `proposer` instead.
    /// @return Address of the proposer.
    /// @custom:legacy
    function PROPOSER() external view returns (address) {
        return proposer;
    }

    /// @notice Getter for the finalizationPeriodSeconds.
    ///         Public getter is legacy and will be removed in the future. Use `finalizationPeriodSeconds` instead.
    /// @return Finalization period in seconds.
    /// @custom:legacy
    function FINALIZATION_PERIOD_SECONDS() external view returns (uint256) {
        return finalizationPeriodSeconds;
    }

    /// @notice Setter for the finalizationPeriodSeconds.
    function setFinalizationPeriodSeconds(uint256 newFinalizationPeriodLength) external onlyOwner {
        // We would never want a value that is larger than a week (like for an OR) and want
        // to avoid anyone being able to DoS the bridge therefore we set an upper bound for the period length
        require(newFinalizationPeriodLength <= 7 days, "L2OutputOracle: Finalization period too long");
        finalizationPeriodSeconds = newFinalizationPeriodLength;
    }

    /// @notice Updates the aggregation verification key.
    /// @param _aggregationVkey The new aggregation verification key.
    function updateAggregationVkey(bytes32 _aggregationVkey) external onlyOwner {
        emit AggregationVkeyUpdated(aggregationVkey, _aggregationVkey);
        aggregationVkey = _aggregationVkey;
    }

    /// @notice Updates the range verification key commitment.
    /// @param _rangeVkeyCommitment The new range verification key commitment.
    function updateRangeVkeyCommitment(bytes32 _rangeVkeyCommitment) external onlyOwner {
        emit RangeVkeyCommitmentUpdated(rangeVkeyCommitment, _rangeVkeyCommitment);
        rangeVkeyCommitment = _rangeVkeyCommitment;
    }

    /// @notice Updates the verifierV3 address.
    /// @param _verifierV3 The new verifierV3 address.
    function updateVerifierV3(address _verifierV3) external onlyOwner {
        emit VerifierUpdated(verifierV3, _verifierV3);
        verifierV3 = _verifierV3;
    }

    /// @notice Setter for the timeLimitOutputRootSubmissionSeconds.
    function setTimeLimitOutputRootSubmissionSeconds(uint256 _timeLimitOutputRootSubmissionSeconds)
        external
        onlyOwner
    {
        timeLimitOutputRootSubmissionSeconds = _timeLimitOutputRootSubmissionSeconds;
    }

    /// @notice Updates the rollup config hash.
    /// @param _rollupConfigHash The new rollup config hash.
    function updateRollupConfigHash(bytes32 _rollupConfigHash) external onlyOwner {
        emit RollupConfigHashUpdated(rollupConfigHash, _rollupConfigHash);
        rollupConfigHash = _rollupConfigHash;
    }

    /// @notice Inserts a new l2Output and its extension into storage.
    /// @param _outputProposal The L2 output proposal.
    /// @param _outputProposalExtension The L2 output proposal extension.
    function _insertL2Output(Types.OutputProposal memory _outputProposal, Types.OutputProposalExtension memory _outputProposalExtension) internal {
        uint256 nextOutputIdx = l2Outputs.length;
        l2Outputs.push(_outputProposal);
        l2OutputsExtension[nextOutputIdx] = _outputProposalExtension;

        emit OutputProposed(_outputProposal.outputRoot, nextOutputIdx, _outputProposal.l2BlockNumber, block.timestamp);
    }

    /// @notice Deletes all output proposals after and including the proposal that corresponds to
    ///         the given output index. Only the challenger address can delete outputs.
    /// @param _l2OutputIndex Index of the first L2 output to be deleted.
    ///                       All outputs after this output will also be deleted.
    function deleteL2Outputs(uint256 _l2OutputIndex) external {
        require(msg.sender == challenger, "L2OutputOracle: only the challenger address can delete outputs");

        // Make sure we're not *increasing* the length of the array.
        require(
            _l2OutputIndex < l2Outputs.length, "L2OutputOracle: cannot delete outputs after the latest output index"
        );

        // Do not allow deleting any outputs that have already been finalized.
        require(
            !isL2OutputFinalized(_l2OutputIndex),
            "L2OutputOracle: cannot delete outputs that have already been finalized"
        );

        _deleteL2Outputs(_l2OutputIndex);
    }

    function _deleteL2Outputs(uint256 _l2OutputIndex) internal {
        uint256 prevNextL2OutputIndex = nextOutputIndex();

        // Delete extension data for all outputs being removed
        for (uint256 i = _l2OutputIndex; i < prevNextL2OutputIndex; i++) {
            delete l2OutputsExtension[i];
        }

        // Use assembly to delete the array elements because Solidity doesn't allow it.
        assembly {
            sstore(l2Outputs.slot, _l2OutputIndex)
        }

        emit OutputsDeleted(prevNextL2OutputIndex, _l2OutputIndex);
    }

    /// @notice Insert a new l2Output without requiring a corresponding proof.
    ///         This can only be called by the proposer and
    ///         1) there are no outputs yet, so we need an initial state to prove transitions from
    ///         2) there was no proof for a prolongued period of time to keep withdrawals live
    /// @param _outputRoot    The L2 output of the checkpoint block.
    /// @param _l2BlockNumber The L2 block number that resulted in _outputRoot.
    function bootstrapL2Output(bytes32 _outputRoot, uint256 _l2BlockNumber, uint64 _senderNonce, address _senderAddress) external {
        require(msg.sender == proposer, "L2OutputOracle: only the proposer address can propose new outputs");

        require(
            _l2BlockNumber >= nextBlockNumber(),
            "L2OutputOracle: block number must be greater than or equal to next expected block number"
        );

        require(
            computeL2Timestamp(_l2BlockNumber) < block.timestamp,
            "L2OutputOracle: cannot propose L2 output in the future"
        );

        require(_outputRoot != bytes32(0), "L2OutputOracle: L2 output proposal cannot be the zero hash");

        uint256 l2OutputsLength = l2Outputs.length;
        // we only allow bootstrapping if we don't have any outputs yet
        if (l2OutputsLength != 0) {
            revert BootstrapAlreadyPerformed();
        }

        _insertL2Output(
            Types.OutputProposal({
                outputRoot: _outputRoot,
                timestamp: uint128(block.timestamp),
                l2BlockNumber: uint128(_l2BlockNumber)
            }),
            Types.OutputProposalExtension({
                senderNonce: _senderNonce,
                senderAddress: _senderAddress
            })
        );
    }

    /// @notice Accepts an outputRoot and verifies that the state transition from the last output root
    ///         to the new one is correct. This function may only be called by the Proposer.
    /// @param _outputRoot    The L2 output of the checkpoint block.
    /// @param _l2BlockNumber The L2 block number that resulted in _outputRoot.
    /// @param _l1BlockNumber The L1 block number for this proof.
    /// @param _proof The aggregation proof that proves the transition from the latest L2 output to the new L2 output.
    /// @param _proverAddress The address of the prover that submitted the proof. Note: proverAddress is not required to
    /// be the tx.origin as there is no reason to front-run the prover in the full validity setting.
    function proposeL2OutputV3(
        bytes32 _outputRoot,
        uint64 _claimNonce,
        address _claimSenderAddress,
        uint256 _l2BlockNumber,
        uint256 _l1BlockNumber,
        bytes memory _proof,
        address _proverAddress
    )
        external
        payable
    {
        require(msg.sender == proposer, "L2OutputOracle: only the proposer address can propose new outputs");

        require(
            _l2BlockNumber >= nextBlockNumber(),
            "L2OutputOracle: block number must be greater than or equal to next expected block number"
        );

        require(
            computeL2Timestamp(_l2BlockNumber) < block.timestamp,
            "L2OutputOracle: cannot propose L2 output in the future"
        );

        require(_outputRoot != bytes32(0), "L2OutputOracle: L2 output proposal cannot be the zero hash");
        uint256 nextOutputIdx = nextOutputIndex();
        require(nextOutputIdx > 0, "L2OutputOracle: not bootstrapped");

        uint256 outputIdx = l2Outputs.length - 1;
        require(
            block.timestamp - l2Outputs[outputIdx].timestamp < timeLimitOutputRootSubmissionSeconds,
            "L2OutputOracle: Over time limit for L2 output proposal"
        );

        bytes32 l1BlockHash = _getBlockHash(_l1BlockNumber);
        if (l1BlockHash == bytes32(0)) {
            l1BlockHash = historicBlockHashes[_l1BlockNumber];
            if (l1BlockHash == bytes32(0)) {
                revert L1BlockHashNotCheckpointed();
            }
        }
        Types.OutputProposalExtension memory outputExt = l2OutputsExtension[outputIdx];
        Types.AggregationOutputs memory publicValues = Types.AggregationOutputs({
            l1Head: l1BlockHash,
            preNonce: outputExt.senderNonce,
            preSenderAddress: outputExt.senderAddress,
            claimNonce: _claimNonce,
            claimSenderAddress: _claimSenderAddress,
            l2PreRoot: l2Outputs[outputIdx].outputRoot,
            claimRoot: _outputRoot,
            claimBlockNum: _l2BlockNumber,
            rollupConfigHash: rollupConfigHash,
            rangeVkeyCommitment: rangeVkeyCommitment,
            proverAddress: _proverAddress
        });

        ISP1Verifier(verifierV3).verifyProof(aggregationVkey, abi.encode(publicValues), _proof);

        _insertL2Output(
            Types.OutputProposal({
                outputRoot: _outputRoot,
                timestamp: uint128(block.timestamp),
                l2BlockNumber: uint128(_l2BlockNumber)
            }),
            Types.OutputProposalExtension({
                senderNonce: _claimNonce,
                senderAddress: _claimSenderAddress
            })
        );
    }

    /// @notice Checkpoints a block hash at a given block number.
    /// @param _blockNumber Block number to checkpoint the hash at.
    /// @dev If the block hash is not available, this will revert.
    function checkpointBlockHash(uint256 _blockNumber) external {
        bytes32 blockHash = _getBlockHash(_blockNumber);
        if (blockHash == bytes32(0)) {
            revert L1BlockHashNotAvailable();
        }
        historicBlockHashes[_blockNumber] = blockHash;
    }

    /// @notice Returns just the relevant information for the OptimismPortal for a withdrawal by index.
    ///         This isolates the OptimismPortal implementation from the implementation details of the L2OO.
    /// @param _l2OutputIndex Index of the output information to return.
    /// @return outputRoot The output root.
    /// @return finalizedTimestamp The timestamp when this output can be considered finalized.
    function getL2OutputRootWithFinalization(uint256 _l2OutputIndex)
        external
        view
        returns (bytes32 outputRoot, uint256 finalizedTimestamp)
    {
        Types.OutputProposal memory proposal = l2Outputs[_l2OutputIndex];
        outputRoot = proposal.outputRoot;
        finalizedTimestamp = proposal.timestamp + finalizationPeriodSeconds;
    }

    /// @notice Query whether an output has been finalized, which requires that both 1) the finalization period passed
    ///         and 2) withdrawals have not been paused centrally through the superchain config contract before the
    ///         finalization period passed
    /// @param _l2OutputIndex Index of the output to check.
    /// @return isFinalized Whether the output can be considered to be finalized or still be deleted
    function isL2OutputFinalized(uint256 _l2OutputIndex) public view returns (bool isFinalized) {
        uint256 finalizationTimestamp = l2Outputs[_l2OutputIndex].timestamp + finalizationPeriodSeconds;
        uint256 pausedTimestamp = superchainConfig.pausedTimestamp();
        // If withdrawals (controlled via superchain config) were paused before the output was finalized, we also
        // consider it not finalized
        return block.timestamp >= finalizationTimestamp
            && (pausedTimestamp == 0 || pausedTimestamp >= finalizationTimestamp);
    }

    /// @notice Returns an output by index. Needed to return a struct instead of a tuple.
    /// @param _l2OutputIndex Index of the output to return.
    /// @return The output at the given index.
    function getL2Output(uint256 _l2OutputIndex) external view returns (Types.OutputProposal memory) {
        return l2Outputs[_l2OutputIndex];
    }

    /// @notice Returns an output extension by index. Needed to return a struct instead of a tuple.
    /// @param _l2OutputIndex Index of the output to return.
    /// @return The output at the given index.
    function getL2OutputExtension(uint256 _l2OutputIndex) external view returns (Types.OutputProposalExtension memory) {
        return l2OutputsExtension[_l2OutputIndex];
    }

    /// @notice Returns the index of the L2 output that checkpoints a given L2 block number.
    ///         Uses a binary search to find the first output greater than or equal to the given
    ///         block.
    /// @param _l2BlockNumber L2 block number to find a checkpoint for.
    /// @return Index of the first checkpoint that commits to the given L2 block number.
    function getL2OutputIndexAfter(uint256 _l2BlockNumber) public view returns (uint256) {
        // Make sure an output for this block number has actually been proposed.
        if (_l2BlockNumber > latestBlockNumber() || l2Outputs.length == 0) {
            revert BlockNotProposed();
        }

        // Find the output via binary search, guaranteed to exist.
        uint256 lo = 0;
        uint256 hi = l2Outputs.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            if (l2Outputs[mid].l2BlockNumber < _l2BlockNumber) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        return lo;
    }

    /// @notice Returns the L2 output proposal that checkpoints a given L2 block number.
    ///         Uses a binary search to find the first output greater than or equal to the given
    ///         block.
    /// @param _l2BlockNumber L2 block number to find a checkpoint for.
    /// @return First checkpoint that commits to the given L2 block number.
    function getL2OutputAfter(uint256 _l2BlockNumber) external view returns (Types.OutputProposal memory) {
        return l2Outputs[getL2OutputIndexAfter(_l2BlockNumber)];
    }

    /// @notice Returns the number of outputs that have been proposed.
    ///         Will revert if no outputs have been proposed yet.
    /// @return The number of outputs that have been proposed.
    function latestOutputIndex() public view returns (uint256) {
        return l2Outputs.length - 1;
    }

    /// @notice Returns the index of the next output to be proposed.
    /// @return The index of the next output to be proposed.
    function nextOutputIndex() public view returns (uint256) {
        return l2Outputs.length;
    }

    /// @notice Returns the block number of the latest submitted L2 output proposal.
    ///         If no proposals been submitted yet then this function will return the starting
    ///         block number.
    /// @return Latest submitted L2 block number.
    function latestBlockNumber() public view returns (uint256) {
        return l2Outputs.length == 0 ? startingBlockNumber : l2Outputs[l2Outputs.length - 1].l2BlockNumber;
    }

    /// @notice Computes the block number of the next L2 block that needs to be checkpointed.
    /// @return Next L2 block number.
    function nextBlockNumber() public view returns (uint256) {
        return latestBlockNumber() + 1;
    }

    /// @notice Returns the L2 timestamp corresponding to a given L2 block number.
    /// @param _l2BlockNumber The L2 block number of the target block.
    /// @return L2 timestamp of the given block.
    function computeL2Timestamp(uint256 _l2BlockNumber) public view returns (uint256) {
        return startingTimestamp + ((_l2BlockNumber - startingBlockNumber) * l2BlockTime);
    }

    /// @notice always have an owner
    function renounceOwnership() public override {
        revert();
    }

    /// @dev Internal function to retrieve the block hash defaulting to EIP-2935 history storage contract.
    function _getBlockHash(uint256 blockNumber) private view returns (bytes32 hash) {
        // If within 256-block history window, use opcode
        hash = blockhash(blockNumber);
        if (hash != bytes32(0)) {
            return hash;
        }

        assembly ("memory-safe") {
            // Store the blockNumber in scratch space
            mstore(0x00, blockNumber)
            mstore(0x20, 0)

            // call history storage address
            pop(staticcall(gas(), HISTORY_STORAGE_ADDRESS, 0x00, 0x20, 0x20, 0x20))

            // load result
            hash := mload(0x20)
        }
    }
}
