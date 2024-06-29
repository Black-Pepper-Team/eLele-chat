// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {PoseidonUnit3L} from "@iden3/contracts/lib/Poseidon.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import {VerifierHelper} from "@solarity/solidity-lib/libs/zkp/snarkjs/VerifierHelper.sol";

import {PoseidonSMT} from "./PoseidonSMT.sol";

contract AuthenticationStorage is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using VerifierHelper for address;

    PoseidonSMT public credentialRegistry;

    address public verifier;

    event Registered(
        address nft,
        uint256 tokenId,
        address nftOwner,
        bytes32 credentialId,
        uint256 deadline
    );

    error NotNFTOwner();
    error CredentialExpired(address sender, bytes32 credentialId);
    error InvalidZKProof();

    constructor() {
        _disableInitializers();
    }

    function __AuthenticationStorage_init(
        address credentialRegistry_,
        address verifier_
    ) external initializer {
        __Ownable_init(_msgSender());

        verifier = verifier_;
        credentialRegistry = PoseidonSMT(credentialRegistry_);
    }

    function setVerifier(address verifier_) external onlyOwner {
        verifier = verifier_;
    }

    function setCredentialRegistry(address credentialRegistry_) external onlyOwner {
        credentialRegistry = PoseidonSMT(credentialRegistry_);
    }

    function register(
        IERC721 nft_,
        uint256 tokenId_,
        address nftOwner_,
        bytes32 credentialId_,
        uint256 deadline_,
        VerifierHelper.ProofPoints calldata zkPoints_
    ) external {
        _requireNFTOwner(nft_, tokenId_);

        // TODO: deadline sanity check to be not too far in the future
        if (block.timestamp > deadline_) {
            revert CredentialExpired(_msgSender(), credentialId_);
        }

        if (!_verifyZKProof(nft_, tokenId_, nftOwner_, credentialId_, deadline_, zkPoints_)) {
            revert InvalidZKProof();
        }

        uint256 value_ = PoseidonUnit3L.poseidon(
            [uint256(uint160(address(nft_))), tokenId_, uint256(uint160(nftOwner_))]
        );

        credentialRegistry.add(credentialId_, bytes32(value_));

        emit Registered(address(nft_), tokenId_, nftOwner_, credentialId_, deadline_);
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @notice Verify credential validity ZK proof.
     */
    function _verifyZKProof(
        IERC721 nft_,
        uint256 tokenId_,
        address nftOwner_,
        bytes32 credentialId_,
        uint256 deadline_,
        VerifierHelper.ProofPoints calldata zkPoints_
    ) internal view returns (bool) {
        uint256[] memory pubSignals_ = new uint256[](5);

        pubSignals_[0] = uint256(credentialId_);
        pubSignals_[1] = uint256(uint160(address(nft_)));
        pubSignals_[2] = tokenId_;
        pubSignals_[3] = uint256(uint160(nftOwner_));
        pubSignals_[4] = deadline_;

        return verifier.verifyProof(pubSignals_, zkPoints_);
    }

    function _requireNFTOwner(IERC721 token_, uint256 tokenId_) private view {
        (bool success_, bytes memory data_) = address(token_).staticcall(
            abi.encodeWithSelector(token_.ownerOf.selector, tokenId_)
        );

        if (!success_ || abi.decode(data_, (address)) != _msgSender()) {
            revert NotNFTOwner();
        }
    }
}
