export declare class MessageDeduplicator {
    private maxSize;
    private seen;
    constructor(maxSize?: number);
    isDuplicate(sender: string, topic: string, nonce: bigint): boolean;
    clear(): void;
}
//# sourceMappingURL=deduplication.d.ts.map