# Dependency maintenance — 2026-11-02

This SDK has no third-party Go module dependencies to update. The go.mod language floor remains Go 1.21. Added CI that builds/tests with patched Go 1.26.10, runs go vet and executes all tests with the race detector. Local race tests and govulncheck passed; the scan reported no reachable findings. No SDK API, module version or release tag was changed.
