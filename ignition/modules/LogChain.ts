import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const LogChainModule = buildModule("LogChainModule", (m) => {
  const logChainV1 = m.contract("LogChainV1");

  const initCall = m.encodeFunctionCall(logChainV1, "initialize", []);

  const proxy = m.contract("ERC1967Proxy", [
    logChainV1,
    initCall
  ]);

  return { logChain: proxy, logChainImplementation: logChainV1 };
});

export default LogChainModule;