# Roadmap

**Long term: all of HCS.** [surface.md](surface.md) is the checklist and it does not shrink.

**Short term: whatever an Aspire integration needs first.** That is a prioritization rule, not a
scope rule. When something is not on this page it is *unordered*, not *unwanted*.

The consumer driving the order is [AspireHcs](https://github.com/joshmakestuff/AspireHcs), which
today boots full VMs and owns its own HCN code. The interesting question is what it would need
from hcsctl to drive Hyper-V-isolated *containers* instead.

---

## How an integration is expected to drive this tool

Worth stating, because it decides which gaps are real:

- **hcsctl is a child process, not a library.** `--json` gives exactly one document on stdout and
  progress on stderr, so the caller parses one shape whether the command worked or not. The exit
  code is hcsctl's own: `0` ran, `1` ran and failed, `64` bad arguments and nothing attempted.
- **A guest process's exit code is never hcsctl's exit code.** It is `exitCode` in the result
  document. Conflating them makes the contract unusable.
- **Long-running guest processes stay attached.** `container exec` streams the guest's stdout and
  stderr for as long as the process lives, so an integration wanting app logs holds the
  `hcsctl container exec` process open and reads its stdout. There is no separate log store to
  query — HCS has no log driver; whoever created the process owns its pipes. This is why there is
  no `container logs` verb and no `--detach`: they would mean hcsctl had to stay resident to pump
  pipes nobody was reading.

---

## P0 — an integration cannot be built without these

### 1. `--env` on `container exec` and `container run`
`ProcessConfig.Environment` is a `map[string]string` that hcsctl does not surface. Aspire's entire
configuration and service-discovery mechanism is environment variables — `WithReference` injects
`services__<name>__<endpoint>__<index>`, and the app reads them at startup. Without `--env` there
is no way to get any of that into a guest process.

Roughly ten lines. It is P0 on need, not on size.

Acceptance: `container exec --env FOO=bar --cmd "cmd /c echo %FOO%"` prints `bar`; repeated
`--env` accumulates (note that `internal/cli` rejects duplicate options by default, deliberately —
repeatability has to be opted into per option); a malformed `--env` is exit 64.

### 2. Attach an endpoint and report the address (issue #5a)
Without an IP there are no Aspire endpoints, no `AllocatedEndpoint`, and no TCP health check —
the integration cannot tell whether the thing it started is serving.

Measured already: putting an endpoint ID in `ContainerConfig.EndpointList` gives a xenon working
DNS and outbound HTTPS. What is missing is the verb, the address in the result document, and
endpoint cleanup on teardown.

Note for whoever picks this up: `HotAttachEndpoint` / `HotDetachEndpoint` in the root package have
no `hcn` equivalent. They would allow attaching to an *already running* container, which is a
nicer shape than fixing `EndpointList` at create time. Worth trying both — this is the one part of
the otherwise-out-of-scope HNS v1 surface that may earn its place.

### 3. Assert the contract automatically (issue #3)
An integration parses our JSON. Silent drift in a field name or an exit code breaks it at runtime
with no signal here. This was deferred to build a real thing first; a real thing now exists, and
the moment something depends on the shape is the moment it needs pinning.

---

## P1 — needed before an integration is pleasant

### 4. Mount host directories into the guest (issue #6)
Seeding config, getting build output back out. `ContainerConfig.MappedDirectories`. Measured: the
host filesystem is otherwise invisible from inside a xenon, which is correct and also total.

### 5. Process control: `Process.Kill`, `WaitTimeout`, `Pid`
An exec can currently hang forever with no way to stop it. An orchestrator that cannot kill what
it started is not an orchestrator. All three methods already exist on the `Process` interface.

### 6. `info` reports capability, not just identity (issue #4)
So an integration fails fast with a usable message instead of failing deep inside `CreateContainer`.
Feed it `osversion.CheckHostAndContainerCompat`, the 18 `hcn.*Supported()` checks,
`GetSupportedFeatures`, and the remaining `cimfs.Is*Supported` probes.

---

## P2 — completes the local dev loop

7. `image export` (`ociwclayer.ExportLayerToTar`) — round-trips an image; also the honest test that
   import is lossless.
8. `LayerExists`, `ExpandScratchSize` — cheap, and a default scratch is small.
9. Interactive exec, `--interactive` and `--tty` (issue #7) — needs `ResizeConsole` and a decision
   about what `--json` even means for an interactive session.
10. The `hcn.*Supported()` checks as a `network capabilities` verb.

---

## P3 — in scope, unordered

11. **Settle legacy wclayer vs `computestorage`.** hcsctl is on legacy *by inheritance* —
    `ociwclayer` uses it, so we do. Nobody decided that. `computestorage` is 14 functions and none
    are wired. This gets more expensive the more layer verbs get built on the current choice, so it
    wants deciding before P2 item 8 rather than after.
12. **CimFS** — 31 symbols, 2 wired. Tempered by hcsshim consuming CIM layers for process-isolated
    containers only.
13. **Network create/delete** (issue #5c) — see the risk note in [findings.md](findings.md).
14. **Process isolation / argon** (issue #8) — cheap to build, permanently elevated at every start.
15. **hcn policies, load balancers, routes** — ACLs, port mappings, DSR.
16. `Container.Modify` — hot-modifying a running system.
17. `ConvertToBaseLayer`, `GetSharedBaseImages`, error-classification helpers.

---

## Standing decisions

| decision | reason |
|---|---|
| Public hcsshim packages only | `pkg/*`, root, `computestorage`, `osversion`. Needing `internal/` means reconsider the design, not fork |
| Hyper-V isolation first | `PrepareLayer` needs an enabled `BUILTIN\Administrators` SID at *every* argon start. Xenon never touches that path |
| Root-package HNS v1 is out | superseded by `hcn`. Single exception under review: `HotAttachEndpoint`/`HotDetachEndpoint`, which have no v2 equivalent |
| `pkg/go-runhcs` / `cmd/runhcs` is out | but not trivially — its container verbs really do overlap ours. Reasoning and revisit triggers in [runhcs.md](runhcs.md) |
| Verbs land with something that ran | every group gets added because it was exercised against a real host, not because the function exists |
