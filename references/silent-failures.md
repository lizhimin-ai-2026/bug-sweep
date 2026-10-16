# Silent failures (the family that never errors)

A whole class of defects never raises: the function returns success, logs are
clean, the endpoint answers 200 - yet the entitlement never arrives, the
capability never appears, the config never takes effect.

**The criterion: do not ask "did it error", ask "did the effect appear".**
Return codes, HTTP statuses, exception logs, unit tests and deploy echoes are
all immune to this family.

## Six measured forms

1. Local declaration vs cloud reality - the config was edited, never
   uploaded; the running entity is the old version.
2. Async timeout budget vs container timeout - the side effect gets cut off
   silently.
3. Shared secret/token configured on one side only - the other side keeps
   failing over to a path that looks healthy.
4. Feature implemented vs user-visible entry - the code exists, the entry
   (share sheet, menu, route) never appears.
5. Fallback passthrough `if (!key) return input;` - missing config silently
   downgrades and drops data.
6. Swallowed errors - empty catch, discarded err, bare recover: the failure
   path exists and reports nothing.

## Where to scan

Anywhere two things "should match": declaration vs live snapshot, declared
vs registered routes, implemented vs exposed entries, configured vs read
channels, source edit vs deployed entity. The five-layer sweep plus deep
kind 4 cover these; the share-capability matrix and the config-channel check
are the two most productive spots.

## How to verify

- Trigger the real user action, on the real entry, and look for the effect.
- Read traces, not declarations: logs record the run, config only the intent.
- Re-read through an independent path: another tool, another entry point.
- For swallowed errors: force the failure (bad key, closed network) and
  confirm something visible happens.

## Four iron rules

1. "No error" is not evidence of "worked".
2. Verification asks about effects, never about error channels.
3. Suspected silent zones are candidates (P2/INFO), never auto-P1: legal
   empty catches exist (telemetry must not block the main flow).
4. A silent zone found is not fixed until its effect is reproduced missing
   and then present after the fix.
