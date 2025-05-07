// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract LogChain {
    event MessageSent(
        address indexed sender,
        bytes ciphertext,
        uint256 timestamp,
        bytes32 indexed topic,
        uint256 nonce
    );

    event Handshake(
        bytes32 indexed recipientHash,      // keccak256("contact:<0xRecipient>")
        address indexed sender,             // msg.sender (EOA or smart account)
        bytes identityPubKey,               // public key that controls sender
        bytes ephemeralPubKey,              // per-message key
        bytes plaintextPayload              // optional greeting or instructions
    );

    event HandshakeResponse(
        bytes32 indexed inResponseTo,       // e.g. keccak256 of original handshake or Alice address
        address indexed responder,          // msg.sender (EOA only for now)
        bytes ciphertext                    // encrypted Bob's pubkey & ephemeral key for Alice
    );

    function respondToHandshake(bytes32 inResponseTo, bytes calldata ciphertext) external {
        emit HandshakeResponse(inResponseTo, msg.sender, ciphertext);
    }

    function sendMessage(
        bytes calldata ciphertext,
        bytes32 topic,
        uint256 timestamp,
        uint256 nonce
    ) external {
        emit MessageSent(msg.sender, ciphertext, timestamp, topic, nonce);
    }

    function initiateHandshake(
        bytes32 recipientHash,              // keccak256("contact:" + lowercaseAddress)
        bytes calldata identityPubKey,      // public key that controls sender
        bytes calldata ephemeralPubKey,     // generated per handshake
        bytes calldata plaintextPayload     // optional human-readable or fallback message
    ) external {
        emit Handshake(recipientHash, msg.sender, identityPubKey, ephemeralPubKey, plaintextPayload);
    }
}
