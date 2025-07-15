export class MessageDeduplicator {
    constructor(maxSize = 10000) {
        this.maxSize = maxSize;
        this.seen = new Set();
    }
    isDuplicate(sender, topic, nonce) {
        const key = `${sender}:${topic}:${nonce}`;
        if (this.seen.has(key)) {
            return true;
        }
        // Simple LRU-like behavior
        if (this.seen.size >= this.maxSize) {
            const firstItem = this.seen.values().next().value;
            if (firstItem !== undefined) {
                this.seen.delete(firstItem);
            }
        }
        this.seen.add(key);
        return false;
    }
    clear() {
        this.seen.clear();
    }
}
