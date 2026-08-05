# Are we rebuilding runhcs?

Partly, in one group, and it is worth being precise about which part rather than waving it off.

`cmd/runhcs` in the hcsshim repo is an OCI runtime for Windows — the runc equivalent. It is real,
it is maintained, and its container verbs are close to ours.

## The overlap is genuine

| runhcs | hcsctl |
|---|---|
| `create` `start` `exec` `kill` `delete` | `container create` `start` `exec` — `kill` is on our roadmap |
| `list` `ps` `state` | `container ls` `ps` `inspect` |
| `pause` `resume` | `container pause` `resume` |
| `run` | `container run` |
| `create-scratch` | `CreateScratchLayer`, inside `container create` |
| `resize-tty` | issue #7 |

That is most of our `container` group. Anyone who says otherwise has not looked.

## What runhcs does not do at all

- **No registry.** It takes an OCI *bundle* — a directory with `config.json` and an already-extracted
  rootfs — that something else must produce. Our entire `image` group (pull, digest-verified
  streaming, import to the windowsfilter store, `layerchain.json`) has no runhcs equivalent.
- **No layer inspection.** No `layer mount` to get a merged volume path and look at it.
- **No network read surface.**
- **A different state model.** runhcs keeps container state in the **registry** (`internal/regstate`)
  and is built to be driven by containerd — hence `shim`, `vmshim`, `log-pipe`, and CNI support.
  It is a runtime for an orchestrator, not a tool for a person or a small integration.

## Why we could not simply reuse its internals even if we wanted to

`cmd/runhcs` imports `internal/hcsoci`, `internal/uvm`, `internal/layers`, `internal/lcow`,
`internal/regstate`, `internal/resources`. All unreachable from outside the module. Being in-repo,
runhcs gets the v2 path we explicitly cannot reach — which is also why hcsctl is on the public v1
`CreateContainer` route.

So the only two real options are **shell out to a `runhcs.exe` we build ourselves**, or **write the
verbs against the public API**, which is what we did.

## The case for adopting runhcs instead

- It is maintained by the people who own HCS.
- OCI-spec-shaped, so containerd, CNI and the OCI bundle ecosystem come along.
- `pkg/go-runhcs` is a public, typed client for driving it — 13 methods, no P/Invoke.
- It has years of edge cases in it that we would otherwise rediscover one at a time.

## The case against, which is why we did not

- **It is not distributed as a binary.** `pkg/go-runhcs` drives a `runhcs.exe` that we would have to
  build from the hcsshim repo, version, sign and ship. That is a build-and-supply-chain problem
  bolted onto a tool whose whole point is being a single self-contained executable.
- **The OCI bundle model is heavier than our use case.** Writing a `config.json` and materializing a
  rootfs directory to run one command in a container is a lot of ceremony for a local dev loop.
- **It does not solve the half we actually needed first.** Image pull and import were the blocking
  problem, and runhcs does neither.
- **Its output contract is not ours.** `--json` producing exactly one document with progress on
  stderr is what makes hcsctl drivable by an integration. runhcs answers to containerd's
  expectations instead.

## Status: decided for now, revisit deliberately

hcsctl owns its container verbs. The duplication is accepted with eyes open, and it is roughly
600 lines in `internal/container` — not the expensive part of this project.

Revisit if any of these become true:

- We want containerd or CNI integration, where being OCI-shaped stops being ceremony and starts
  being the point.
- The v1 `CreateContainer` route runs out — for instance if something needs a feature only the v2
  document exposes and there is no public path to it.
- Microsoft starts shipping `runhcs.exe` as a distributable artifact.

If it is revisited, the honest comparison is not "runhcs vs our container package" but "runhcs +
a bundle builder + a binary distribution story vs our container package".
