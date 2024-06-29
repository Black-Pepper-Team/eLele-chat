// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract ERC721Mock is ERC721 {
    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    function mint(address to_, uint256 tokenId_) public {
        _mint(to_, tokenId_);
    }

    function burn(uint256 tokenId_) public {
        _burn(tokenId_);
    }
}
