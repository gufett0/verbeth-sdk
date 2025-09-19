// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// As per ERC-1271
interface IERC1271Wallet {
  function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

error ERC1271Revert(bytes error);
error ERC6492DeployFailed(bytes error);

contract UniversalSigValidator {
  bytes32 private constant ERC6492_DETECTION_SUFFIX = 0x6492649264926492649264926492649264926492649264926492649264926492;
  bytes4 private constant ERC1271_SUCCESS = 0x1626ba7e;

  // ECDSA secp256k1 curve order / 2 (for malleability check)
  uint256 private constant SECP256K1N_OVER_TWO =
    0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

  function isValidSigImpl(
    address _signer,
    bytes32 _hash,
    bytes calldata _signature,
    bool allowSideEffects,
    bool tryPrepare
  ) public returns (bool) {
    uint contractCodeLen = address(_signer).code.length;
    bytes memory sigToValidate;

    // Order strictly defined in EIP-6492:
    // 1. Check for ERC-6492 envelope (counterfactual)
    // 2. If contract code exists, try ERC-1271
    // 3. Fallback to ECDSA ecrecover
    bool isCounterfactual = bytes32(_signature[_signature.length-32:_signature.length]) == ERC6492_DETECTION_SUFFIX;
    if (isCounterfactual) {
      address create2Factory;
      bytes memory factoryCalldata;
      (create2Factory, factoryCalldata, sigToValidate) = abi.decode(
        _signature[0:_signature.length-32],
        (address, bytes, bytes)
      );

      if (contractCodeLen == 0 || tryPrepare) {
        (bool success, bytes memory err) = create2Factory.call(factoryCalldata);
        if (!success) revert ERC6492DeployFailed(err);
      }
    } else {
      sigToValidate = _signature;
    }

    // ERC-1271 validation path
    if (isCounterfactual || contractCodeLen > 0) {
      try IERC1271Wallet(_signer).isValidSignature(_hash, sigToValidate) returns (bytes4 magicValue) {
        bool isValid = magicValue == ERC1271_SUCCESS;

        // retry assuming prefix is a prepare call
        if (!isValid && !tryPrepare && contractCodeLen > 0) {
          return isValidSigImpl(_signer, _hash, _signature, allowSideEffects, true);
        }

        if (contractCodeLen == 0 && isCounterfactual && !allowSideEffects) {
          // to avoid side effects, return result via revert(bool)
          assembly {
            mstore(0x00, isValid)
            revert(0x00, 0x20)
          }
        }

        return isValid;
      } catch (bytes memory err) {
        if (!tryPrepare && contractCodeLen > 0) {
          return isValidSigImpl(_signer, _hash, _signature, allowSideEffects, true);
        }
        revert ERC1271Revert(err);
      }
    }

    // ECDSA verification
    require(_signature.length == 65, "SignatureValidator#recoverSigner: invalid sig length");
    bytes32 r = bytes32(_signature[0:32]);
    bytes32 s = bytes32(_signature[32:64]);
    uint8 v = uint8(_signature[64]);

    // added anti malleability (reject high-s values)
    require(uint256(s) <= SECP256K1N_OVER_TWO, "SignatureValidator: invalid s value");

    // normalize v (reference only required 27/28)
    if (v != 27 && v != 28) revert("SignatureValidator: invalid v value");

    return ecrecover(_hash, v, r, s) == _signer;
  }

  function isValidSigWithSideEffects(address _signer, bytes32 _hash, bytes calldata _signature)
    external returns (bool)
  {
    return this.isValidSigImpl(_signer, _hash, _signature, true, false);
  }

  function isValidSig(address _signer, bytes32 _hash, bytes calldata _signature)
    external returns (bool)
  {
    try this.isValidSigImpl(_signer, _hash, _signature, false, false) returns (bool isValid) {
      return isValid;
    } catch (bytes memory error) {
      // no-side-effects path, result is returned via revert(bool)
      if (error.length == 32) {
        return abi.decode(error, (bool));
      }
      revert();
    }
  }
}
