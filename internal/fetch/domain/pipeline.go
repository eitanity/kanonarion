package domain

// PipelineVersion identifies this release of the fetch pipeline. Bump it
// whenever any stage logic changes, so old records are not confused with new
// ones. It lives in the domain so that ports can tell a current record from one
// a superseded pipeline wrote.
const PipelineVersion = "0.6.0"
