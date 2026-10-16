import { API_VERSION } from "./service";

export function formatId(id: string): string {
    return API_VERSION + ":" + id.trim().toLowerCase();
}
