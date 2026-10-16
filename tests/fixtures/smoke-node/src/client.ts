import { loadProfile } from "./service";

const ROUTES: string[] = ["/", "/profile", "/settings"];

export function renderRoutes(profileId: string): string[] {
    const profile = loadProfile(profileId) as { version?: string } | null;
    const version = profile ? profile.version : undefined;
    const suffix = version ? "?v=" + version : "";
    return ROUTES.map((route) => route + suffix);
}
