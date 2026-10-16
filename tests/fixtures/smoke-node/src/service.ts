import { cachedKey, readRecord } from "./util_a";

export const API_VERSION = "v1";

export function parsePayload(raw: string): unknown {
    try {
        return JSON.parse(raw);
    } catch (e) {}
}

export function loadProfile(id: string): unknown {
    const raw = readRecord(cachedKey(id));
    return parsePayload(raw);
}
