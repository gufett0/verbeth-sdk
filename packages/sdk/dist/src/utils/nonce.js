const nonceRegistry = {};
export function getNextNonce(sender, topic) {
    const key = `${sender}-${topic}`;
    nonceRegistry[key] = (nonceRegistry[key] ?? 0n) + 1n;
    return nonceRegistry[key];
}
