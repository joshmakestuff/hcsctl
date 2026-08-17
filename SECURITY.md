# Security

hcsctl runs with the privileges of the caller and drives the Windows Host Compute Service
directly. Elevated verbs (`image import`, `container run --isolation process`, `layer mount`)
say so in `hcsctl help`; nothing escalates on its own.

Report a vulnerability privately through
[GitHub security advisories](https://github.com/joshmakestuff/hcsctl/security/advisories/new)
rather than a public issue. Include the hcsctl version, the Windows build, and reproduction
steps. This is a personal project without a response-time commitment; reports are read and
answered as time allows.

Release assets are built by `release.yml` from the tagged commit; verify downloads against the
`SHA256SUMS` published with each release.
