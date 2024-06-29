// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import {Paginator} from "@solarity/solidity-lib/libs/arrays/Paginator.sol";
import {SetHelper} from "@solarity/solidity-lib/libs/arrays/SetHelper.sol";
import {DynamicSet} from "@solarity/solidity-lib/libs/data-structures/DynamicSet.sol";
import {VerifierHelper} from "@solarity/solidity-lib/libs/zkp/snarkjs/VerifierHelper.sol";

import {PoseidonSMT} from "./PoseidonSMT.sol";

contract Chat is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using VerifierHelper for address;

    using SetHelper for DynamicSet.StringSet;
    using DynamicSet for DynamicSet.StringSet;
    using Paginator for DynamicSet.StringSet;

    using Paginator for EnumerableSet.UintSet;
    using EnumerableSet for EnumerableSet.UintSet;

    struct Message {
        string message;
        uint256 timestamp;
    }

    uint256 public constant DEADLINE_VALIDITY_WINDOW = 1 hours;

    address public postMessageVerifier;

    PoseidonSMT public credentialStorage;

    mapping(address => DynamicSet.StringSet) private _chatByNFT;
    mapping(address => EnumerableSet.UintSet) private _timestampsByChat;

    event MessagePosted(IERC721 nft, string message);

    error CredentialRootInvalid();
    error DeadlineNotMet(uint256 deadline_, uint256 currectTime_);
    error InvalidZKProof();

    constructor() {
        _disableInitializers();
    }

    function __Chat_init(
        address authenticationStorage_,
        address postMessageVerifier_
    ) external initializer {
        __Ownable_init(_msgSender());

        postMessageVerifier = postMessageVerifier_;
        credentialStorage = PoseidonSMT(authenticationStorage_);
    }

    function setPostMessageVerifier(address postMessageVerifier_) external onlyOwner {
        postMessageVerifier = postMessageVerifier_;
    }

    function setCredentialStorage(address credentialStorage_) external onlyOwner {
        credentialStorage = PoseidonSMT(credentialStorage_);
    }

    function postMessage(
        IERC721 nft_,
        string memory message_,
        bytes32 root_,
        uint256 deadline_,
        VerifierHelper.ProofPoints calldata zkPoints_
    ) external {
        if (!credentialStorage.isRootValid(root_)) {
            revert CredentialRootInvalid();
        }

        if (deadline_ < block.timestamp) {
            revert DeadlineNotMet(deadline_, block.timestamp);
        }

        if (!_verifyZKProof(nft_, message_, root_, deadline_, zkPoints_)) {
            revert InvalidZKProof();
        }

        _chatByNFT[address(nft_)].add(message_);
        _timestampsByChat[address(nft_)].add(block.timestamp);

        emit MessagePosted(nft_, message_);
    }

    function listMessages(
        address nft_,
        uint256 offset_,
        uint256 limit_
    ) external view returns (Message[] memory) {
        string[] memory messages_ = _chatByNFT[nft_].part(offset_, limit_);
        uint256[] memory timestamps_ = _timestampsByChat[nft_].part(offset_, limit_);

        Message[] memory result_ = new Message[](messages_.length);

        for (uint256 i = 0; i < messages_.length; i++) {
            result_[i] = Message(messages_[i], timestamps_[i]);
        }

        return result_;
    }

    /**
     * @notice Verify posting message eligibility via ZK proof
     */
    function _verifyZKProof(
        IERC721 nft_,
        string memory message_,
        bytes32 root_,
        uint256 deadline_,
        VerifierHelper.ProofPoints memory zkPoints_
    ) internal view returns (bool) {
        uint256[] memory pubSignals_ = new uint256[](4);

        pubSignals_[0] = uint256(uint160(address(nft_)));
        pubSignals_[1] = uint256(root_);
        pubSignals_[2] = uint256(
            keccak256(abi.encodePacked(message_)) &
                0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        );
        pubSignals_[3] = deadline_;

        return postMessageVerifier.verifyProof(pubSignals_, zkPoints_);
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
