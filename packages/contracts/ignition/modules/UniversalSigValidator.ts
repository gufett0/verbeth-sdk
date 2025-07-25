import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const UniversalSigValidatorModule = buildModule("UniversalSigValidatorModule", (m) => {
  const universalSigValidator = m.contract("UniversalSigValidator");
  return { universalSigValidator };
});

export default UniversalSigValidatorModule;
