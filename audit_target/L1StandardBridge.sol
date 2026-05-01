// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Predeploys } from "src/libraries/Predeploys.sol";
import { StandardBridge } from "src/universal/StandardBridge.sol";
import { ISemver } from "src/universal/ISemver.sol";
import { CrossDomainMessenger } from "src/universal/CrossDomainMessenger.sol";
import { L1CrossDomainMessenger } from "src/L1/L1CrossDomainMessenger.sol";
import { OptimismPortal } from "src/L1/OptimismPortal.sol";
import { SuperchainConfig } from "src/L1/SuperchainConfig.sol";
import { Constants } from "src/libraries/Constants.sol";
import { AccessControlPausable } from "src/universal/AccessControlPausable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { L2OutputOracle } from "src/L1/L2OutputOracle.sol";
import { Types } from "src/libraries/Types.sol";
import { Hashing } from "src/libraries/Hashing.sol";
import { StateVerifier } from "src/libraries/StateVerifier.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ResolverRegistry } from "./ResolverRegistry.sol";
import { IEscapeResolver } from "src/L1/IEscapeResolver.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @custom:proxied
/// @title L1StandardBridge
/// @notice The L1StandardBridge is responsible for transfering ETH and ERC20 tokens between L1 and
///         L2. In the case that an ERC20 token is native to L1, it will be escrowed within this
///         contract. If the ERC20 token is native to L2, it will be burnt. Before Bedrock, ETH was
///         stored within this contract. After Bedrock, ETH is instead stored inside the
///         OptimismPortal contract.
///         NOTE: this contract is not intended to support all variations of ERC20 tokens. Examples
///         of some token types that may not be properly supported by this contract include, but are
///         not limited to: tokens with transfer fees, rebasing tokens, and tokens with blocklists.
contract L1StandardBridge is StandardBridge, ReentrancyGuardUpgradeable, ISemver {
    /// @notice Semantic version.
    /// @custom:semver 2.3.0
    string public constant version = "2.3.0";

    using SafeERC20 for IERC20;

    uint256[14] spacer_49_0_448;

    /// @notice List for (User => (Token => Amount Escaped))
    mapping(address => mapping(address => uint256)) public escapedAmount;

    /// @notice Emitted when user escapes ERC20 tokens.
    /// @param user address of the user that escaped the tokens.
    /// @param localToken address of the localToken that was escaped from the contract.
    /// @param remoteToken address of the corresponding remoteToken.
    /// @param amount amount of localToken ERC20 removed from the contract.
    event ERC20Escape(address indexed user, address indexed localToken, address indexed remoteToken, uint256 amount);

    /// @notice Emitted when user escaped ERC20 token through resolver.
    /// @param user address of the user that escaped the tokens.
    /// @param l2Contract contract on L2 that held the tokens.
    /// @param localToken address of the localToken that was escaped from the contract.
    /// @param remoteToken address of the corresponding remoteToken.
    /// @param amount  amount of localToken ERC20 removed from the contract.
    event ERC20EscapeResolver(
        address indexed user,
        address indexed l2Contract,
        address indexed localToken,
        address remoteToken,
        uint256 amount
    );

    /// @notice Constructs the L1StandardBridge contract.
    constructor() StandardBridge() {
        initialize({ _messenger: CrossDomainMessenger(address(0)), _superchainConfig: SuperchainConfig(address(0)) });
    }

    /// @notice Initializer.
    /// @param _messenger        Contract for the CrossDomainMessenger on this network.
    /// @param _superchainConfig Contract for the SuperchainConfig on this network.
    function initialize(CrossDomainMessenger _messenger, SuperchainConfig _superchainConfig) public initializer {
        __StandardBridge_init({
            _messenger: _messenger,
            _otherBridge: StandardBridge(payable(Predeploys.L2_STANDARD_BRIDGE)),
            _accessController: AccessControlPausable(_superchainConfig)
        });
    }

    /// @notice The access controller is also the superchain config. To avoid storing it twice, only use a getter here
    function superchainConfig() external view returns (SuperchainConfig) {
        return SuperchainConfig(address(accessController));
    }

    /// @inheritdoc StandardBridge
    function paused() public view override returns (bool) {
        return accessController.paused();
    }

    /// @notice Allows EOAs to bridge ETH by sending directly to the bridge.
    receive() external payable override onlyEOA {
        _initiateETHDeposit(msg.sender, msg.sender, RECEIVE_DEFAULT_GAS_LIMIT, bytes(""));
    }

    /// @notice Internal function for initiating an ETH deposit.
    /// @param _from        Address of the sender on L1.
    /// @param _to          Address of the recipient on L2.
    /// @param _minGasLimit Minimum gas limit for the deposit message on L2.
    /// @param _extraData   Optional data to forward to L2.
    function _initiateETHDeposit(address _from, address _to, uint32 _minGasLimit, bytes memory _extraData) internal {
        _initiateBridgeETH(_from, _to, msg.value, _minGasLimit, _extraData);
    }

    /// @notice Allows users to escape ERC20 tokens if no output root has been published for over 30 days.
    /// @param _localToken Address of the token on L1.
    /// @param _remoteToken Address of the corresponding token on L2.
    /// @param _isRemoteTokenUpgradable If the L2 token is an upgradable contract or not 
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's storage root.
    /// @param _accountState State of the ERC20 token contract on L2.
    /// @param _stateProof Proof of the ERC20 contract state.
    /// @param _tokenBalance Balance the user had of the ERC20 on L2.
    /// @param _storageProof Proof of value on the storage slot with the user balance.
    function escapeERC20(
        address _localToken,
        address _remoteToken,
        bool _isRemoteTokenUpgradable,
        Types.OutputRootProof calldata _outputRootProof,
        Types.AccountState calldata _accountState,
        bytes[] calldata _stateProof,
        uint256 _tokenBalance,
        bytes[] calldata _storageProof
    )
        external
        nonReentrant
    {
        _verifyOutputRoot(_outputRootProof);

        _verifyState(_remoteToken, _accountState, _stateProof, _outputRootProof.stateRoot);

        bytes32 storageKey = _getBalanceSlot(msg.sender, _isRemoteTokenUpgradable);

        _verifyBalance(storageKey, _tokenBalance, _storageProof, _accountState.storageRoot);

        escapedAmount[msg.sender][_remoteToken] += _tokenBalance;

        require(escapedAmount[msg.sender][_remoteToken] == _tokenBalance, "L1StandardBridge: Already escaped tokens.");

        deposits[_localToken][_remoteToken] -= _tokenBalance;

        IERC20(_localToken).safeTransfer(msg.sender, _tokenBalance);

        emit ERC20Escape(msg.sender, _localToken, _remoteToken, _tokenBalance);
    }

    /// @notice Allows users to escape ERC20 tokens from a smart contract through a resolver contract if no output root
    /// has been published for over 30 days.
    /// @param _localToken Address of the token on L1.
    /// @param _remoteToken Address of the corresponding token on L2.
    /// @param _isRemoteTokenUpgradable If the L2 token is an upgradable contract or not 
    /// @param _outputRootProof Inclusion proof of the L2ToL1MessagePasser contract's storage root.
    /// @param _accountState State of the ERC20 token contract on L2.
    /// @param _stateProof Proof of the ERC20 contract state.
    /// @param _tokenBalance Balance the smart contract had of the ERC20 on L2.
    /// @param _storageProof Proof of value on the storage slot with the user balance.
    /// @param _resolverData Extra data needed for the resolver to determine escape.
    function escapeERC20ThroughResolver(
        address _localToken,
        address _remoteToken,
        bool _isRemoteTokenUpgradable,
        Types.OutputRootProof calldata _outputRootProof,
        Types.AccountState calldata _accountState,
        bytes[] calldata _stateProof,
        uint256 _tokenBalance,
        bytes[] calldata _storageProof,
        Types.ResolverData calldata _resolverData
    )
        external
        nonReentrant
    {
        _verifyOutputRoot(_outputRootProof);

        _verifyState(_remoteToken, _accountState, _stateProof, _outputRootProof.stateRoot);

        _verifyBalance(
            _getBalanceSlot(_resolverData.l2Contract, _isRemoteTokenUpgradable), _tokenBalance, _storageProof, _accountState.storageRoot
        );

        uint256 _amountToUser;
        {
            address _resolver = _getResolverRegistry().resolvers(_resolverData.l2Contract);
            if (_resolver == address(0)) {
                revert("L1StandardBridge: No Resolver Contract Registered");
            }

            _amountToUser = IEscapeResolver(_resolver).userEscapableERC20Balance(
                msg.sender, _remoteToken, _outputRootProof.stateRoot, _resolverData.data
            );
        }
        escapedAmount[_resolverData.l2Contract][_remoteToken] += _amountToUser;

        require(_amountToUser <= _tokenBalance, "L1StandardBridge: Invalid amount from resolver");
        require(
            escapedAmount[_resolverData.l2Contract][_remoteToken] <= _tokenBalance,
            "L1StandardBridge: Already escaped tokens."
        );

        deposits[_localToken][_remoteToken] -= _amountToUser;

        IERC20(_localToken).safeTransfer(msg.sender, _amountToUser);

        emit ERC20EscapeResolver(msg.sender, _resolverData.l2Contract, _localToken, _remoteToken, _amountToUser);
    }

    function _verifyOutputRoot(Types.OutputRootProof calldata _outputRootProof) internal view {
        L2OutputOracle l2Oracle = _getL2OutputOracle();

        Types.OutputProposal memory lastSubmittedRoot = l2Oracle.getL2Output(l2Oracle.latestOutputIndex());
        uint256 timeLimitOutputRootSubmissionSeconds = l2Oracle.timeLimitOutputRootSubmissionSeconds();

        require(
            lastSubmittedRoot.timestamp + timeLimitOutputRootSubmissionSeconds < block.timestamp,
            "L1StandardBridge: Not enough time has passed to escape."
        );

        require(
            lastSubmittedRoot.outputRoot == Hashing.hashOutputRootProof(_outputRootProof),
            "L1StandardBridge: invalid output root proof"
        );
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
            "L1StandardBridge: Invalid state proof."
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
            "L1StandardBridge: Invalid storage proof."
        );
    }

    function _getL2OutputOracle() internal view returns (L2OutputOracle) {
        return OptimismPortal(L1CrossDomainMessenger(address(messenger)).portal()).l2Oracle();
    }

    function _getResolverRegistry() internal view returns (ResolverRegistry) {
        return OptimismPortal(L1CrossDomainMessenger(address(messenger)).portal()).resolverRegistry();
    }

    function _getBalanceSlot(address _user,bool _isRemoteTokenUpgradable) internal pure returns (bytes32) {
        if (_isRemoteTokenUpgradable) {
            // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ERC20")) - 1)) & ~bytes32(uint256(0xff))
            return keccak256(abi.encode(uint256(uint160(_user)), uint256(0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00)));
        } else {
            return keccak256(abi.encode(uint256(uint160(_user)), uint256(0)));
        }
    }
}
