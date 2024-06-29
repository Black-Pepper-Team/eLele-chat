// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {PoseidonUnit2L, PoseidonUnit3L} from "@iden3/contracts/lib/Poseidon.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {SparseMerkleTree} from "@solarity/solidity-lib/libs/data-structures/SparseMerkleTree.sol";

contract PoseidonSMT is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using SparseMerkleTree for SparseMerkleTree.Bytes32SMT;

    uint256 public constant ROOT_VALIDITY = 1 hours;

    address public authenticationStorage;

    mapping(bytes32 => uint256) internal _roots;

    SparseMerkleTree.Bytes32SMT internal _bytes32Tree;

    event RootUpdated(bytes32 root);

    error Unauthorized();

    modifier onlyAuthenticationStorage() {
        _onlyAuthenticationStorage();
        _;
    }

    modifier withRootUpdate() {
        _saveRoot();
        _;
        _notifyRoot();
    }

    constructor() {
        _disableInitializers();
    }

    function __PoseidonSMT_init(
        address authenticationStorage_,
        uint256 treeHeight_
    ) external initializer {
        __Ownable_init(_msgSender());

        _bytes32Tree.initialize(uint32(treeHeight_));
        _bytes32Tree.setHashers(_hash2, _hash3);

        authenticationStorage = authenticationStorage_;
    }

    /**
     * @notice Adds the new element to the tree.
     */
    function add(
        bytes32 keyOfElement_,
        bytes32 element_
    ) external onlyAuthenticationStorage withRootUpdate {
        _bytes32Tree.add(keyOfElement_, element_);
    }

    /**
     * @notice Removes the element from the tree.
     */
    function remove(bytes32 keyOfElement_) external onlyAuthenticationStorage withRootUpdate {
        _bytes32Tree.remove(keyOfElement_);
    }

    /**
     * @notice Updates the element in the tree.
     */
    function update(
        bytes32 keyOfElement_,
        bytes32 newElement_
    ) external onlyAuthenticationStorage withRootUpdate {
        _bytes32Tree.update(keyOfElement_, newElement_);
    }

    /**
     * @notice Gets Merkle (inclusion/exclusion) proof of the element.
     */
    function getProof(bytes32 key_) external view returns (SparseMerkleTree.Proof memory) {
        return _bytes32Tree.getProof(key_);
    }

    /**
     * @notice Gets the SMT root
     */
    function getRoot() external view returns (bytes32) {
        return _bytes32Tree.getRoot();
    }

    /**
     * @notice Gets the node info by its key.
     */
    function getNodeByKey(bytes32 key_) external view returns (SparseMerkleTree.Node memory) {
        return _bytes32Tree.getNodeByKey(key_);
    }

    /**
     * @notice Check if the SMT root is valid. Zero root in always invalid and latest root is always a valid one.
     */
    function isRootValid(bytes32 root_) external view returns (bool) {
        if (root_ == bytes32(0)) {
            return false;
        }

        return isRootLatest(root_) || _roots[root_] + ROOT_VALIDITY > block.timestamp;
    }

    /**
     * @notice Check if the SMT root is a latest one
     */
    function isRootLatest(bytes32 root_) public view returns (bool) {
        return _bytes32Tree.getRoot() == root_;
    }

    function _saveRoot() internal {
        _roots[_bytes32Tree.getRoot()] = block.timestamp;
    }

    function _notifyRoot() internal {
        emit RootUpdated(_bytes32Tree.getRoot());
    }

    function _onlyAuthenticationStorage() internal view {
        if (authenticationStorage != _msgSender()) {
            revert Unauthorized();
        }
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function _hash2(bytes32 element1_, bytes32 element2_) internal pure returns (bytes32) {
        return bytes32(PoseidonUnit2L.poseidon([uint256(element1_), uint256(element2_)]));
    }

    function _hash3(
        bytes32 element1_,
        bytes32 element2_,
        bytes32 element3_
    ) internal pure returns (bytes32) {
        return
            bytes32(
                PoseidonUnit3L.poseidon(
                    [uint256(element1_), uint256(element2_), uint256(element3_)]
                )
            );
    }
}
