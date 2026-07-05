module example.com/supplychain/directives/excludenewer

go 1.23

require example.com/dep v1.2.0

// High-risk class: excluding a version newer than the resolved one
// can force resolution off a CVE-patched release.
exclude example.com/dep v1.3.0
