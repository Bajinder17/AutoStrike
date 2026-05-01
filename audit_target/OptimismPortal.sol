// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { SafeCall } from "src/libraries/SafeCall.sol";
import { L2OutputOracle } from "src/L1/L2OutputOracle.sol";
import { SystemConfig } from "src/L1/SystemConfig.sol";
import { SuperchainConfig } from "src/L1/SuperchainConfig.sol";
import { Constants } from "src/libraries/Constants.sol";
import { Types } from "src/libraries/Types.sol";
import { Hashing } from "src/libraries/Hashing.sol";
import { SecureMerkleTrie } from "src/libraries/trie/SecureMerkleTrie.sol";
import { StateVerifier } from "src/libraries/StateVerifier.sol";
import { AddressAliasHelper } from "src/vendor/AddressAliasHelper.sol";
import { ResourceMetering } from "src/L1/ResourceMetering.sol";
import { ISemver } from "src/universal/ISemver.sol";
import { Predeploys } from "src/libraries/Predeploys.sol";
import { IEscapeResolver } from "src/L1/IEscapeResolver.sol";
import { ResolverRegistry } from "src/L1/ResolverRegistry.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { Constants } from "src/libraries/Constants.sol";
import { Encoding } from "src/libraries/Encoding.sol";
import { WithdrawTreeVerifier } from "src/libraries/WithdrawTreeVerifier.sol";

/// @custom:proxied
/// @title OptimismPortal
/// @notice The OptimismPortal is a low-level contract responsible for passing messages between L1
///         and L2. Messages sent directly to the OptimismPortal have no form of replayability.
///         Users are encouraged to use the L1CrossDomainMessenger for a higher-level interface.
/// @notice The withdrawal verification method was ported from Scroll
contract OptimismPortal is Initializable, ReentrancyGuardUpgradeable, ResourceMetering, ISemver {
    /// @notice Represents a proven withdrawal.
    /// @custom:field outputRoot    Root of the L2 output this was proven against.
    /// @custom:field timestamp     Timestamp at which the withdrawal was proven.
    /// @custom:field l2OutputIndex Index of the output this was proven against.
    struct ProvenWithdrawal {
        bytes32 outputRoot;
        uint128 timestamp;
        uint128 l2OutputIndex;
    }

    /// @notice Version of the deposit event.
    uint256 internal constant DEPOSIT_VERSION = 0;

    /// @notice The L2 gas limit set when eth is deposited using the receive() function.
    uint64 internal constant RECEIVE_DEFAULT_GAS_LIMIT = 100_000;

    /// @notice Address of the L2 account which initiated a withdrawal in this transaction.
    ///         If the of this variable is the default L2 sender address, then we are NOT inside of
    ///         a call to finalizeWithdrawalTransaction.
    address public l2Sender;

    /// @notice A list of withdrawal hashes which have been successfully finalized.
    mapping(bytes32 => bool) public finalizedWithdrawals;

    /// @notice Mapping of withdrawal hashes to `ProvenWithdrawal` data
    mapping(bytes32 => ProvenWithdrawal) public provenWithdrawals;

    /// @notice The address of the Superchain Config contract.
    SuperchainConfig public superchainConfig;

    uint256[24] spacer_54_0_768;

    /// @notice Contract of the L2OutputOracle.
    /// @custom:network-specific
    L2OutputOracle public l2Oracle;

    /// @notice Contract of the SystemConfig.
    /// @custom:network-specific
    SystemConfig public systemConfig;

    /// @notice Registry for Escape Resolvers
    ResolverRegistry public resolverRegistry;

    /// @notice Mapping from address to amount of Eth escaped
    mapping(address => uint256) public amountEscaped;

    /// @notice Mapping from address to amount of WETH escaped
    mapping(address => uint256) public amountWETHEscaped;

    /// @notice Emitted when a transaction is deposited from L1 to L2.
    ///         The parameters of this event are read by the rollup node and used to derive deposit
    ///         transactions on L2.
    /// @param from       Address that triggered the deposit transaction.
    /// @param to         Address that the deposit transaction is directed to.
    /// @param version    Version of this deposit transaction event.
    /// @param opaqueData ABI encoded deposit data to be parsed off-chain.
    event TransactionDeposited(address indexed from, address indexed to, uint256 indexed version, bytes opaqueData);

    /// @notice Legacy, removed but kept for backwards compatibility in the bindings
    /// @notice Emitted when a withdrawal transaction is proven.
    /// @param withdrawalHash Hash of the withdrawal transaction.
    /// @param from           Address that triggered the withdrawal transaction.
    /// @param to             Address that the withdrawal transaction is directed to.
    event WithdrawalProven(bytes32 indexed withdrawalHash, address indexed from, address indexed to);

    /// @notice Emitted when a withdrawal transaction is finalized.
    /// @param withdrawalHash Hash of the withdrawal transaction.
    /// @param success        Whether the withdrawal transaction was successful.
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success);

    /// @notice Emitted when an Eth escape happens.
    /// @param user address that performed the escape.
    /// @param amount amount of Eth removed from the contract.
    event ETHEscaped(address indexed user, uint256 amount);

    /// @notice Emitted when an Eth escape through a resolver happens.
    /// @param l2Contract Address of the L2 contract that held the funds.
    /// @param user address that performed the escape.
    /// @param amount amount of Eth removed from the contract.
    event ETHEscapedResolver(address indexed l2Contract, address indexed user, uint256 amount);

    /// @notice Emitted when an WETH escape happens.
    /// @param user address that performed the escape.
    /// @param amount amount of Eth removed from the contract.
    event WETHEscaped(address indexed user, uint256 amount);

    /// @notice Emitted when an Eth escape through a resolver happens.
    /// @param l2Contract Address of the L2 contract that held the funds.
    /// @param user address that performed the escape.
    /// @param amount amount of Eth removed from the contract.
    event WETHEscapedResolver(address indexed l2Contract, address indexed user, uint256 amount);

    /// @notice Reverts when paused.
    modifier whenNotPaused() {
        require(paused() == false, "OptimismPortal: paused");
        _;
    }

    /// @notice Semantic version.
    /// @custom:semver 2.2.0
    string public constant version = "2.2.0";

    /// @notice Constructs the OptimismPortal contract.
    constructor() {
        initialize({
            _l2Oracle: L2OutputOracle(address(0)),
            _systemConfig: SystemConfig(address(0)),
            _superchainConfig: SuperchainConfig(address(0)),
            _resolverRegistry: ResolverRegistry(address(0))
        });
    }

    /// @notice Initializer.
    /// @param _l2Oracle Contract of the L2OutputOracle.
    /// @param _systemConfig Contract of the SystemConfig.
    /// @param _superchainConfig Contract of the SuperchainConfig.
    function initialize(
        L2OutputOracle _l2Oracle,
        SystemConfig _systemConfig,
        SuperchainConfig _superchainConfig,
        ResolverRegistry _resolverRegistry
    )
        public
        initializer
    {
        l2Oracle = _l2Oracle;
        systemConfig = _systemConfig;
        superchainConfig = _superchainConfig;
        resolverRegistry = _resolverRegistry;

        if (l2Sender == address(0)) {
            l2Sender = Constants.DEFAULT_L2_SENDER;
        }
        __ResourceMetering_init();
    }

    /// @notice Getter function for the address of the guardian. This will be removed in the future, use
    /// `SuperchainConfig.guardian()` instead.
    /// @notice Address of the guardian.
    /// @custom:legacy
    function guardian() public view returns (address) {
        return superchainConfig.guardian();
    }

    /// @notice Getter for the current paused status.
    function paused() public view returns (bool paused_) {
        paused_ = superchainConfig.paused();
    }

    /// @notice Computes the minimum gas limit for a deposit.
    ///         The minimum gas limit linearly increases based on the size of the calldata.
    ///         This is to prevent users from creating L2 resource usage without paying for it.
    ///         This function can be used when interacting with the portal to ensure forwards
    ///         compatibility.
    /// @param _byteCount Number of bytes in the calldata.
    /// @return The minimum gas limit for a deposit.
    function minimumGasLimit(uint64 _byteCount) public pure returns (uint64) {
        return _byteCount * 40 + 21000;
    }

    /// @notice Accepts value so that users can send ETH directly to this contract and have the
    ///         funds be deposited to their address on L2. This is intended as a convenience
    ///         function for EOAs. Contracts should call the depositTransaction() function directly
    ///         otherwise any deposited funds will be lost due to address aliasing.
    // solhint-disable-next-line ordering
    receive() external payable {
        depositTransaction(msg.sender, msg.value, RECEIVE_DEFAULT_GAS_LIMIT, false, bytes(""));
    }

    /// @notice Accepts ETH value without triggering a deposit to L2.
    ///         This function mainly exists for the sake of the migration between the legacy
    ///         Optimism system and Bedrock.
    function donateETH() external payable {
        // Intentionally empty.
    }

    /// @notice Getter for the resource config.
    ///         Used internally by the ResourceMetering contract.
    ///         The SystemConfig is the source of truth for the resource config.
    /// @return ResourceMetering ResourceConfig
    function _resourceConfig() internal view override returns (ResourceMetering.ResourceConfig memory) {
        return systemConfig.resourceConfig();
    }

    /// @notice Proves and finalizes a withdrawal transaction.
    /// @param _tx              Withdrawal transaction to finalize.
    /// @param _l2OutputIndex   L2 output index to prove against.
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's withdrawal root.
    /// @param _withdrawalProof Inclusion proof of the withdrawal in L2ToL1MessagePasser contract.
    function proveWithdrawalTransaction(
        Types.WithdrawalTransaction memory _tx,
        uint256 _l2OutputIndex,
        Types.OutputRootProof calldata _outputRootProof,
        bytes[] calldata _withdrawalProof
    )
        external
        whenNotPaused
    {
        // Prevent users from creating a deposit transaction where this address is the message
        // sender on L2
        require(_tx.target != address(this), "OptimismPortal: you cannot send messages to the portal contract");

        // Make sure that the l2Sender has not yet been set. The l2Sender is set to a value other
        // than the default value when a withdrawal transaction is being finalized. This check is
        // a defacto reentrancy guard.
        require(l2Sender == Constants.DEFAULT_L2_SENDER, "OptimismPortal: function cannot be reentered");

        // Get the output root and finalization time. This will revert if there is no output root for the given block
        // number.
        (bytes32 outputRoot, uint256 outputFinalizedAt) = l2Oracle.getL2OutputRootWithFinalization(_l2OutputIndex);

        // A withdrawal must wait at least the finalization period before it can be finalized.
        require(
            block.timestamp >= outputFinalizedAt,
            "OptimismPortal: proven withdrawal finalization period has not elapsed"
        );

        // Verify that the output root can be generated with the elements in the proof.
        require(
            outputRoot == Hashing.hashOutputRootProof(_outputRootProof), "OptimismPortal: invalid output root proof"
        );

        // using the withdrawal hash as a unique identifier.
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);

        // Nonce has a version stored as a bit in the highest byte - this is masked out here.
        (uint240 msgNonce, uint16 msgVersion) = Encoding.decodeVersionedNonce(_tx.nonce);

        // Withdrawal proof verficaction with respect to withdrawal root
        if(msgVersion == 1) {
            // Verification of Merkle trie proof for old withdrawals.
            // Compute the storage slot of the withdrawal hash in the L2ToL1MessagePasser contract.
            // Refer to the Solidity documentation for more information on how storage layouts are
            // computed for mappings.
            bytes32 storageKey = keccak256(
                abi.encode(
                    withdrawalHash,
                    uint256(0) // The withdrawals mapping is at the first slot in the layout.
                )
            );
            // Verify that the hash of this withdrawal was stored in the L2toL1MessagePasser contract
            // on L2. If this is true, under the assumption that the SecureMerkleTrie does not have
            // bugs, then we know that this withdrawal was actually triggered on L2 and can therefore
            // be relayed on L1.
            require(
                SecureMerkleTrie.verifyInclusionProof(
                    abi.encode(storageKey), hex"01", _withdrawalProof, _outputRootProof.messagePasserStorageRoot
                ),
                "OptimismPortal: invalid withdrawal inclusion proof, msgVersion=1"
            );
        } else if (msgVersion == 2) {
            // Verification of Merkle tree proof for new withdrawals.
            require(
                WithdrawTreeVerifier.verifyMerkleProof(
                    _outputRootProof.messagePasserStorageRoot, withdrawalHash, msgNonce, _withdrawalProof[0]
                ),
                "OptimismPortal: invalid withdrawal inclusion proof, msgVersion=2"
            );
        } else {
            revert("OptimismPortal: invalid message version");
        }

        // Check that this withdrawal has not already been finalized, this is replay protection.
        require(finalizedWithdrawals[withdrawalHash] == false, "OptimismPortal: withdrawal has already been finalized");

        // Mark the withdrawal as finalized so it can't be replayed.
        finalizedWithdrawals[withdrawalHash] = true;

        // Set the l2Sender so contracts know who triggered this withdrawal on L2.
        l2Sender = _tx.sender;

        // Trigger the call to the target contract. We use a custom low level method
        // SafeCall.callWithMinGas to ensure two key properties
        //   1. Target contracts cannot force this call to run out of gas by returning a very large
        //      amount of data (and this is OK because we don't care about the returndata here).
        //   2. The amount of gas provided to the execution context of the target is at least the
        //      gas limit specified by the user. If there is not enough gas in the current context
        //      to accomplish this, `callWithMinGas` will revert.
        bool success = SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, _tx.data);

        // Reset the l2Sender back to the default value.
        l2Sender = Constants.DEFAULT_L2_SENDER;

        // All withdrawals are immediately finalized. Replayability can
        // be achieved through contracts built on top of this contract
        emit WithdrawalFinalized(withdrawalHash, success);

        // Reverting here is useful for determining the exact gas cost to successfully execute the
        // sub call to the target contract if the minimum gas limit specified by the user would not
        // be sufficient to execute the sub call.
        if (success == false && tx.origin == Constants.ESTIMATION_ADDRESS) {
            revert("OptimismPortal: withdrawal failed");
        }
    }

    /// @notice Finalizes a withdrawal transaction. Keeping this function for legacy transactions that
    ///         were proven before the single step withdrawal process was introduced.
    /// @param _tx Withdrawal transaction to finalize.
    function finalizeWithdrawalTransaction(Types.WithdrawalTransaction memory _tx) external whenNotPaused {
        // Make sure that the l2Sender has not yet been set. The l2Sender is set to a value other
        // than the default value when a withdrawal transaction is being finalized. This check is
        // a defacto reentrancy guard.
        require(l2Sender == Constants.DEFAULT_L2_SENDER, "OptimismPortal: function cannot be reentered");

        // Grab the proven withdrawal from the `provenWithdrawals` map.
        bytes32 withdrawalHash = Hashing.hashWithdrawal(_tx);
        ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[withdrawalHash];

        // A withdrawal can only be finalized if it has been proven. We know that a withdrawal has
        // been proven at least once when its timestamp is non-zero. Unproven withdrawals will have
        // a timestamp of zero.
        require(provenWithdrawal.timestamp != 0, "OptimismPortal: withdrawal has not been proven yet");

        // As a sanity check, we make sure that the proven withdrawal's timestamp is greater than
        // starting timestamp inside the L2OutputOracle. Not strictly necessary but extra layer of
        // safety against weird bugs in the proving step.
        require(
            provenWithdrawal.timestamp >= l2Oracle.startingTimestamp(),
            "OptimismPortal: withdrawal timestamp less than L2 Oracle starting timestamp"
        );

        // Get the output root and finalization time. This will revert if there is no output root for the given block
        // number.
        (bytes32 outputRoot, uint256 outputFinalizedAt) =
            l2Oracle.getL2OutputRootWithFinalization(provenWithdrawal.l2OutputIndex);

        // A proven withdrawal must wait at least the finalization period before it can be
        // finalized. This waiting period can elapse in parallel with the waiting period for the
        // output the withdrawal was proven against. In effect, this means that the minimum
        // withdrawal time is proposal submission time + finalization period.
        require(
            block.timestamp >= outputFinalizedAt,
            "OptimismPortal: proven withdrawal finalization period has not elapsed"
        );

        // Check that the output root that was used to prove the withdrawal is the same as the
        // current output root for the given output index. An output root may change if it is
        // deleted by the challenger address and then re-proposed.
        require(
            outputRoot == provenWithdrawal.outputRoot,
            "OptimismPortal: output root proven is not the same as current output root"
        );

        // Check that this withdrawal has not already been finalized, this is replay protection.
        require(finalizedWithdrawals[withdrawalHash] == false, "OptimismPortal: withdrawal has already been finalized");

        // Mark the withdrawal as finalized so it can't be replayed.
        finalizedWithdrawals[withdrawalHash] = true;

        // Set the l2Sender so contracts know who triggered this withdrawal on L2.
        l2Sender = _tx.sender;

        // Trigger the call to the target contract. We use a custom low level method
        // SafeCall.callWithMinGas to ensure two key properties
        //   1. Target contracts cannot force this call to run out of gas by returning a very large
        //      amount of data (and this is OK because we don't care about the returndata here).
        //   2. The amount of gas provided to the execution context of the target is at least the
        //      gas limit specified by the user. If there is not enough gas in the current context
        //      to accomplish this, `callWithMinGas` will revert.
        bool success = SafeCall.callWithMinGas(_tx.target, _tx.gasLimit, _tx.value, _tx.data);

        // Reset the l2Sender back to the default value.
        l2Sender = Constants.DEFAULT_L2_SENDER;

        // All withdrawals are immediately finalized. Replayability can
        // be achieved through contracts built on top of this contract
        emit WithdrawalFinalized(withdrawalHash, success);

        // Reverting here is useful for determining the exact gas cost to successfully execute the
        // sub call to the target contract if the minimum gas limit specified by the user would not
        // be sufficient to execute the sub call.
        if (success == false && tx.origin == Constants.ESTIMATION_ADDRESS) {
            revert("OptimismPortal: withdrawal failed");
        }
    }

    /// @notice Accepts deposits of ETH and data, and emits a TransactionDeposited event for use in
    ///         deriving deposit transactions. Note that if a deposit is made by a contract, its
    ///         address will be aliased when retrieved using `tx.origin` or `msg.sender`. Consider
    ///         using the CrossDomainMessenger contracts for a simpler developer experience.
    /// @param _to         Target address on L2.
    /// @param _value      ETH value to send to the recipient.
    /// @param _gasLimit   Amount of L2 gas to purchase by burning gas on L1.
    /// @param _isCreation Whether or not the transaction is a contract creation.
    /// @param _data       Data to trigger the recipient with.
    function depositTransaction(
        address _to,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    )
        public
        payable
        whenNotPaused
        metered(_gasLimit)
    {
        // Just to be safe, make sure that people specify address(0) as the target when doing
        // contract creations.
        if (_isCreation) {
            require(_to == address(0), "OptimismPortal: must send to address(0) when creating a contract");
        }

        // Prevent depositing transactions that have too small of a gas limit. Users should pay
        // more for more resource usage.
        require(_gasLimit >= minimumGasLimit(uint64(_data.length)), "OptimismPortal: gas limit too small");

        // Prevent the creation of deposit transactions that have too much calldata. This gives an
        // upper limit on the size of unsafe blocks over the p2p network. 120kb is chosen to ensure
        // that the transaction can fit into the p2p network policy of 128kb even though deposit
        // transactions are not gossipped over the p2p network.
        require(_data.length <= 120_000, "OptimismPortal: data too large");

        // Transform the from-address to its alias if the caller is a contract.
        address from = msg.sender;
        if (msg.sender != tx.origin) {
            from = AddressAliasHelper.applyL1ToL2Alias(msg.sender);
        }

        // Compute the opaque data that will be emitted as part of the TransactionDeposited event.
        // We use opaque data so that we can update the TransactionDeposited event in the future
        // without breaking the current interface.
        bytes memory opaqueData = abi.encodePacked(msg.value, _value, _gasLimit, _isCreation, _data);

        // Emit a TransactionDeposited event so that the rollup node can derive a deposit
        // transaction for this deposit.
        emit TransactionDeposited(from, _to, DEPOSIT_VERSION, opaqueData);
    }

    /// @notice Determine if a given output is finalized.
    ///         Reverts if the call to l2Oracle.getL2Output reverts.
    ///         Returns a boolean otherwise.
    /// @param _l2OutputIndex Index of the L2 output to check.
    /// @return Whether or not the output is finalized.
    function isOutputFinalized(uint256 _l2OutputIndex) external view returns (bool) {
        (, uint256 outputFinalizedAt) = l2Oracle.getL2OutputRootWithFinalization(_l2OutputIndex);
        return block.timestamp >= outputFinalizedAt;
    }

    /// @notice Function to withdraw ETH that user had on L2 if more than 30 days passed since output root was
    /// published.
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's storage root.
    /// @param _accountState State of user account on L2.
    /// @param _proof Proof of account state on L2.
    function escapeETH(
        Types.OutputRootProof calldata _outputRootProof,
        Types.AccountState calldata _accountState,
        bytes[] calldata _proof
    )
        external
        nonReentrant
    {
        _verifyOutputRoot(_outputRootProof);

        _verifyState(msg.sender, _accountState, _proof, _outputRootProof.stateRoot);

        amountEscaped[msg.sender] += _accountState.balance;

        require(amountEscaped[msg.sender] == _accountState.balance, "OptimismPortal: Already escaped ETH balance.");

        bool success = SafeCall.send(msg.sender, _accountState.balance);
        if (success == false) {
            revert("OptimismPortal: escape failed");
        }

        emit ETHEscaped(msg.sender, _accountState.balance);
    }

    /// @notice Function to withdraw WETH that user had on L2 if more than 30 days passed since output root was
    /// published.
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's storage root.
    /// @param _accountState State of of WETH contract on L2.
    /// @param _stateProof Proof of account state of WETH on L2.
    /// @param _wethBalance User balance of WETH.
    /// @param _storageProof Proof of value on the storage slot with the user balance.
    function escapeWETH(
        Types.OutputRootProof calldata _outputRootProof,
        Types.AccountState calldata _accountState,
        bytes[] calldata _stateProof,
        uint256 _wethBalance,
        bytes[] calldata _storageProof
    )
        external
        nonReentrant
    {
        _verifyOutputRoot(_outputRootProof);

        _verifyState(Predeploys.WETH9, _accountState, _stateProof, _outputRootProof.stateRoot);

        bytes32 storageKey = _getWETHBalanceSlot(msg.sender);

        _verifyBalance(storageKey, _wethBalance, _storageProof, _accountState.storageRoot);

        amountWETHEscaped[msg.sender] += _wethBalance;

        require(amountWETHEscaped[msg.sender] == _wethBalance, "OptimismPortal: Already escaped WETH balance.");

        bool success = SafeCall.send(msg.sender, _wethBalance);
        if (success == false) {
            revert("OptimismPortal: escape failed");
        }

        emit WETHEscaped(msg.sender, _wethBalance);
    }

    /// @notice Function to remove ETH to user that smart contract had on L2 if more than 30 days passed since output
    /// root was published through a resolver contract.
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's storage root.
    /// @param _accountstate State of of smart contract account on L2.
    /// @param _proof Proof of account state of smart contract on L2.
    /// @param _l2Contract Address of the L2 smart contract that users wants to escape assets from.
    /// @param _data Extra data needed for the resolver contract.
    function escapeETHThroughResolver(
        Types.OutputRootProof calldata _outputRootProof,
        Types.AccountState calldata _accountstate,
        bytes[] calldata _proof,
        address _l2Contract,
        bytes memory _data
    )
        external
        nonReentrant
    {
        _verifyOutputRoot(_outputRootProof);

        _verifyState(_l2Contract, _accountstate, _proof, _outputRootProof.stateRoot);

        address _resolver = ResolverRegistry(resolverRegistry).resolvers(_l2Contract);
        if (_resolver == address(0)) {
            revert("OptimismPortal: No Resolver Contract Registered");
        }

        uint256 _amountToUser = IEscapeResolver(_resolver).userEscapableETHBalance(msg.sender, _accountstate, _data);

        amountEscaped[_l2Contract] += _amountToUser;

        require(_amountToUser <= _accountstate.balance, "OptimismPortal: Invalid amount from resolver");
        require(amountEscaped[_l2Contract] <= _accountstate.balance, "OptimismPortal: Already escaped ETH balance.");

        bool success = SafeCall.send(msg.sender, _amountToUser);
        if (success == false) {
            revert("OptimismPortal: escape failed");
        }

        emit ETHEscapedResolver(_l2Contract, msg.sender, _amountToUser);
    }

    /// @notice Allows users to escape ERC20 tokens from a smart contract through a resolver contract if no output root
    /// has been published for over 30 days.
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's storage root.
    /// @param _wethState State of the WETH token contract on L2.
    /// @param _stateProof Proof of the WETH contract state.
    /// @param _tokenBalance Balance the smart contract had of WETH on L2.
    /// @param _storageProof Proof of value on the storage slot with the user balance.
    /// @param _resolverData Extra data needed for the resolver to determine escape.
    function escapeWETHThroughResolver(
        Types.OutputRootProof calldata _outputRootProof,
        Types.AccountState calldata _wethState,
        bytes[] calldata _stateProof,
        uint256 _tokenBalance,
        bytes[] calldata _storageProof,
        Types.ResolverData calldata _resolverData
    )
        external
        nonReentrant
    {
        _verifyOutputRoot(_outputRootProof);

        _verifyState(Predeploys.WETH9, _wethState, _stateProof, _outputRootProof.stateRoot);

        _verifyBalance(
            _getWETHBalanceSlot(_resolverData.l2Contract), _tokenBalance, _storageProof, _wethState.storageRoot
        );

        uint256 _amountToUser;
        {
            address _resolver = ResolverRegistry(resolverRegistry).resolvers(_resolverData.l2Contract);
            if (_resolver == address(0)) {
                revert("OptimismPortal: No Resolver Contract Registered");
            }

            _amountToUser = IEscapeResolver(_resolver).userEscapableERC20Balance(
                msg.sender, Predeploys.WETH9, _outputRootProof.stateRoot, _resolverData.data
            );
        }
        amountWETHEscaped[_resolverData.l2Contract] += _amountToUser;

        require(_amountToUser <= _tokenBalance, "OptimismPortal: Invalid amount from resolver");
        require(
            amountWETHEscaped[_resolverData.l2Contract] <= _tokenBalance,
            "OptimismPortal: Already escaped WETH balance."
        );

        bool success = SafeCall.send(msg.sender, _amountToUser);
        if (success == false) {
            revert("OptimismPortal: escape failed");
        }

        emit WETHEscapedResolver(_resolverData.l2Contract, msg.sender, _amountToUser);
    }

    function _verifyState(
        address _account,
        Types.AccountState calldata _accountState,
        bytes[] memory _proof,
        bytes32 _stateRoot
    )
        internal
        pure
    {
        require(
            StateVerifier.verifyAccountState(_account, _accountState, _proof, _stateRoot),
            "OptimismPortal: Invalid account state proof."
        );
    }

    function _verifyOutputRoot(Types.OutputRootProof calldata _outputRootProof) internal view {
        Types.OutputProposal memory lastSubmittedRoot = l2Oracle.getL2Output(l2Oracle.latestOutputIndex());
        uint256 timeLimitOutputRootSubmissionSeconds = l2Oracle.timeLimitOutputRootSubmissionSeconds();

        require(
            lastSubmittedRoot.timestamp + timeLimitOutputRootSubmissionSeconds < block.timestamp,
            "OptimismPortal: Not enough time has passed to escape."
        );

        require(
            lastSubmittedRoot.outputRoot == Hashing.hashOutputRootProof(_outputRootProof),
            "OptimismPortal: Invalid output root proof"
        );
    }

    function _verifyBalance(
        bytes32 _storageKey,
        uint256 _tokenBalance,
        bytes[] memory _storageProof,
        bytes32 _storageRoot
    )
        internal
        pure
    {
        require(
            StateVerifier.verifyERC20Balance(_storageKey, _tokenBalance, _storageProof, _storageRoot),
            "OptimismPortal: Invalid storage proof."
        );
    }

    function _getWETHBalanceSlot(address _user) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(uint160(_user)), uint256(3)));
    }
}
