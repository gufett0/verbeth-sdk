const nonceRegistry: Record<string, bigint> = {};

export function getNextNonce(sender: string, topic: string): bigint {
  const key = `${sender}-${topic}`;
  nonceRegistry[key] = (nonceRegistry[key] ?? 0n) + 1n;
  return nonceRegistry[key];
}
