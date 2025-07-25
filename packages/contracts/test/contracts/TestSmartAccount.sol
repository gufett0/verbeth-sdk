// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.24;

// /**
//  * TestSmartAccount
//  * ----------------
//  * Minimal single-owner smart-account for local ERC-4337 tests.
//  *
//  * • Inherits   OpenZeppelin “community-contracts” Account,
//  *              which supplies nonce handling, validateUserOp(), etc.
//  * • Adds       SignerECDSA to reuse its _rawSignatureValidation helper.
//  * • Stores     the EntryPoint passed at deployment in an immutable variable.
//  */

// import "@openzeppelin/community-contracts/contracts/account/Account.sol";
// import "@openzeppelin/community-contracts/contracts/utils/cryptography/signers/SignerECDSA.sol";

// import "@openzeppelin/contracts/interfaces/IERC1271.sol";
// import "@openzeppelin/contracts/interfaces/draft-IERC4337.sol"; // IEntryPoint (draft till ERC is final)

// contract TestSmartAccount is Account, SignerECDSA {
//     /// EntryPoint that this account trusts (e.g. for local Anvil deployments)
//     IEntryPoint private immutable _entryPoint;

//     /**
//      * Executes a low-level call to a target address, with the given value and data.
//      * This function is called by the EntryPoint to execute UserOps.
//      *
//      * @param target The address to call.
//      * @param value The amount of Ether to send with the call.
//      * @param data The calldata to pass to the target address.
//      */
//     /// @dev This function is called by the EntryPoint to execute UserOps.
//     function execute(
//         address target,
//         uint256 value,
//         bytes calldata data 
//     ) external payable virtual {
//         require(
//             msg.sender == address(_entryPoint),
//             "SA: caller _must_ be EntryPoint"
//         );

//         (bool ok, bytes memory ret) = target.call{value: value}(data);

//         if (!ok) {
//             // propagate the revert reason from the target call
//             if (ret.length > 0) {
//                 /// @solidity memory-safe-assembly
//                 assembly {
//                     revert(add(ret, 0x20), mload(ret))
//                 }
//             }
//             revert("SA: low-level call failed");
//         }
//     }

//     /**
//      * @param ep      Address of the EntryPoint contract (local or live network)
//      * @param signer  EOA that will sign UserOps / messages for this account
//      */
//     constructor(IEntryPoint ep, address signer) {
//         _entryPoint = ep; // remember the chosen EntryPoint
//         _setSigner(signer); // helper from SignerECDSA (stores the owner)
//     }

//     /**
//      * Called by EntryPoint.validateUserOp() to know which EntryPoint
//      * this account recognises.  Keeps the same visibility/signature
//      * as in OZ Account, therefore is marked `override`.
//      */
//     function entryPoint() public view override returns (IEntryPoint) {
//         return _entryPoint;
//     }

//     /**
//      * Allows dApps or on-chain contracts to check a signature via ERC-1271.
//      * Returns the 4-byte “magic value” on success, 0xffffffff on failure.
//      */
//     function isValidSignature(
//         bytes32 hash,
//         bytes calldata sig
//     ) public view returns (bytes4) {
//         return
//             _rawSignatureValidation(hash, sig)
//                 ? IERC1271.isValidSignature.selector // 0x1626ba7e
//                 : bytes4(0xffffffff); // invalid signature
//     }

//     /**
//      * OZ `Account.validateSignature()` delegates here to convert
//      * an ECDSA signature into “validationData” (0 = OK).
//      *
//      * No `override` keyword needed in current OZ community‐contracts,
//      * because `_validateSignature()` is not declared `virtual` there.
//      * If a future version marks it `virtual`, simply add `override`.
//      */
//     function _validateSignature(
//         bytes32 hash,
//         bytes calldata sig
//     ) internal view returns (uint256) {
//         return _rawSignatureValidation(hash, sig) ? 0 : 1;
//     }
// }
