# Approved OpenRC adapter implementation plan

Implements the approved OpenRC worker supervision design. Installation and service activation remain separate operator steps.

1. Render native OpenRC services and a root-owned isolated Python launcher around the unchanged package_supervisor builder/BOOTSTRAP/schema2 bundle; never shell-evaluate its argv.
2. Add the bounded private executable RAM adapter with explicit refusal checks, held descriptors, active supervisor-lock refusal and ordinary unmount only. Render private staging files and manifest; no automatic install/start.
3. Add focused portable regressions and run the existing loader/supervisor suite. Review the namespace boundary, argument handling, mount refusal and graceful-stop behavior. Preserve all core supervisor bytes and exact persistent-bind/own-Tailscale contracts.
4. Submit source for CI/review. Before activation, verify native Alpine/OpenRC tooling, lifecycle/PID/TERM/respawn, Docker loss/recovery, storage UUID refusal, tmpfs flags and cgroup limits. Portable tests do not establish that forcibly killing the supervisor stops its running Docker containers, or reproduce systemd BindsTo semantics. Native namespace installation remains a separately scoped concrete operation, with no host reboot.
