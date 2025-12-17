/**
 * Storage interface for persisting membership VCs.
 */
export interface VcStorage {
    /** Retrieve the stored VC JWT, or null if none exists */
    get(): string | null;
    /** Store a VC JWT */
    set(jwt: string): void;
    /** Remove the stored VC */
    clear(): void;
}
/**
 * Creates a browser storage implementation using LocalStorage.
 * Use this in browser environments.
 *
 * @returns VcStorage implementation backed by LocalStorage
 */
export declare function createBrowserStorage(): VcStorage;
/**
 * Creates an in-memory storage implementation.
 * Use this for Node.js environments or testing.
 *
 * @returns VcStorage implementation backed by memory
 */
export declare function createMemoryStorage(): VcStorage;
//# sourceMappingURL=storage.d.ts.map