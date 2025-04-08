import { LogChain } from '../typechain-types';

export async function getNextNonce(
  contract: LogChain,
  sender: string,
  topic: string
): Promise<bigint> {
  const last = await contract.lastNonce(sender, topic);
  return last + 1n;
}
