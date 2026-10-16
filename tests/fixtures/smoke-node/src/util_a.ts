import { formatId } from "./util_b";

const store = new Map<string, string>();

export function cachedKey(id: string): string {
    return "profile:" + formatId(id);
}

export function readRecord(key: string): string {
    const value = store.get(key);
    if (value === undefined) {
        throw new Error("cache miss: " + key);
    }
    return value;
}

export function writeRecord(key: string, value: string): void {
    try {
        store.set(key, value);
    } catch (e) {
        console.error("cache write failed for " + key, e);
        throw e;
    }
}
