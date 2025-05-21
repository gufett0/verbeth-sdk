// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * Test Smart Account for testing EIP-1271 signatures
 */
contract TestSmartAccount is IERC1271 {
    address public owner;
    
    constructor(address _owner) {
        owner = _owner;
    }
    
    /**
     * EIP-1271 compliant signature validation
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) 
        external 
        view 
        override 
        returns (bytes4) 
    {

        if (signature.length != 65) {
            return 0xffffffff;
        }
        
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            r := calldataload(add(signature.offset, 0x00))
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        
        address recovered = ecrecover(hash, v, r, s);
        

        if (recovered == owner && recovered != address(0)) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }
    
    function execute(address dest, uint256 value, bytes calldata func) 
        external 
        returns (bytes memory) 
    {
        require(msg.sender == owner, "not owner");
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, "call failed");
        return result;
    }
    
    receive() external payable {}
}