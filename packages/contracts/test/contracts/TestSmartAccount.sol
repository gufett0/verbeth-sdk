// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {SignerECDSA} from "@openzeppelin/contracts/utils/cryptography/signers/SignerECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/// @notice Minimal single-owner smart account for local ERC-4337 tests.
contract TestSmartAccount is Account, SignerECDSA {
    /// @dev EntryPoint this account trusts (e.g. local Anvil one).
    IEntryPoint private immutable _entryPoint;

    /// @param ep     EntryPoint address (v0.8 or your local EP)
    /// @param signer EOA that signs UserOps/messages for this account
    constructor(IEntryPoint ep, address signer) SignerECDSA(signer) {
        _entryPoint = ep;
    }

    /// @inheritdoc Account
    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @dev Called by the EntryPoint to execute UserOps.
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable onlyEntryPoint {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            if (ret.length > 0) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            revert("SA: low-level call failed");
        }
    }

    /// @dev ERC-1271 signature check.
    function isValidSignature(
        bytes32 hash,
        bytes calldata sig
    ) public view returns (bytes4) {
        return _rawSignatureValidation(hash, sig)
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }
}
