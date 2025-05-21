export class MessageDeduplicator {
    private seen = new Set<string>();
    
    constructor(private maxSize: number = 10000) {}
    
    isDuplicate(sender: string, topic: string, nonce: bigint): boolean {
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
    
    clear(): void {
      this.seen.clear();
    }
  }