// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract LogChain {
    event MessageSent(
        address indexed sender,
        bytes ciphertext,
        uint256 timestamp,
        bytes32 indexed topic
    );

    function sendMessage(bytes calldata ciphertext, bytes32 topic, uint256 timestamp) external {
        emit MessageSent(msg.sender, ciphertext, timestamp, topic);
    }
}
