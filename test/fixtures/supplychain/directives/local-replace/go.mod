module example.com/supplychain/directives/localreplace

go 1.23

require example.com/dep v1.2.0

// Highest-risk class: local-path replace has no remote checksum to
// verify against.
replace example.com/dep => ../../../local/dep
