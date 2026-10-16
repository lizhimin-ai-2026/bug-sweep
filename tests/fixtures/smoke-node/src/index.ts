import { cachedKey, writeRecord } from "./util_a";
import { loadProfile } from "./service";
import { renderRoutes } from "./client";

interface BootstrapReport {
    profile: unknown;
    routes: string[];
    routeCount: number;
    payloadSize: number;
    startedAt: number;
    finishedAt: number;
    elapsedMs: number;
    digest: string;
    summary: string;
    status: string;
}

function bootstrap(): BootstrapReport {
    const started = Date.now();
    const profileId = "main";
    writeRecord(cachedKey(profileId), "{}");
    const profile = loadProfile(profileId);
    const routes = renderRoutes(profileId);
    const routeCount = routes.length;
    const finished = Date.now();
    const elapsedMs = finished - started;
    const payload = JSON.stringify(profile);
    const payloadSize = payload.length;
    const digest = payloadSize + ":" + routeCount + ":" + elapsedMs;
    const summary = "bootstrap " + profileId + " routes=" + routeCount;
    const warnings: string[] = [];
    if (payloadSize === 0) {
        warnings.push("empty payload");
    }
    if (routeCount === 0) {
        warnings.push("no routes registered");
    }
    const status = warnings.length === 0 ? "ok" : "degraded";
    const lines: string[] = [];
    lines.push("start " + started);
    lines.push("profile " + profileId);
    lines.push("routes " + routeCount);
    lines.push("payload " + payloadSize);
    lines.push("elapsed " + elapsedMs);
    lines.push("digest " + digest);
    lines.push("status " + status);
    lines.push("finish " + finished);
    const tags = routes.map((route) => route.replace("/", ":"));
    const tagCount = tags.length;
    const flat = tags.join(",");
    const report: BootstrapReport = {
        profile: profile,
        routes: routes,
        routeCount: routeCount,
        payloadSize: payloadSize,
        startedAt: started,
        finishedAt: finished,
        elapsedMs: elapsedMs,
        digest: digest,
        summary: summary,
        status: status,
    };
    console.log(lines.join("\n"));
    console.log(flat + " tags=" + tagCount);
    return report;
}

bootstrap();
