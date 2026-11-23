package tinylower

// v0440 is read off github.com/tinygo-org/tinygo@v0.44.0 compiler/; each entry
// names the line that emits the call. A name assembled from strings is cited at
// the line that assembles it.
//
// Not modelled, because each is a declaration with no body that a later TinyGo
// pass replaces, so an edge to it reaches nothing: internal/task.getGoroutineStackSize
// (goroutine.go:122), runtime.trackPointer (gc.go:111), and the per-interface
// $typeassert and $invoke functions (interface.go:1300) the compiler synthesises.
var v0440 = &Table{
	version:           "0.44.0",
	binOpFallsThrough: false,
	callees: map[Op][]Callee{
		OpMapMake:            {rt("hashmapMakeGeneric")},                             // map.go:63
		OpMapKeyFuncsString:  {rt("hashmapStringPtrHash"), rt("hashmapStringEqual")}, // map.go:51, map.go:52
		OpMapKeyFuncsBinary:  {rt("hash32"), rt("memequal")},                         // map.go:54, map.go:55
		OpMapGetString:       {rt("hashmapStringGet")},                               // map.go:168
		OpMapGetBinary:       {rt("hashmapBinaryGet")},                               // map.go:174
		OpMapGetGeneric:      {rt("hashmapGenericGet")},                              // map.go:176
		OpMapSetString:       {rt("hashmapStringSet")},                               // map.go:198
		OpMapSetBinary:       {rt("hashmapBinarySet")},                               // map.go:202
		OpMapSetGeneric:      {rt("hashmapGenericSet")},                              // map.go:204
		OpMapDeleteString:    {rt("hashmapStringDelete")},                            // map.go:220
		OpMapDeleteBinary:    {rt("hashmapBinaryDelete")},                            // map.go:226
		OpMapDeleteGeneric:   {rt("hashmapGenericDelete")},                           // map.go:228
		OpMapClear:           {rt("hashmapClear")},                                   // map.go:243
		OpMapLen:             {rt("hashmapLen")},                                     // compiler.go:2126
		OpMapNext:            {rt("hashmapNext")},                                    // map.go:262
		OpKeyHashString:      {rt("hashmapStringPtrHash")},                           // map.go:455
		OpKeyHashFloat32:     {rt("hashmapFloat32Hash")},                             // map.go:460
		OpKeyHashFloat64:     {rt("hashmapFloat64Hash")},                             // map.go:462
		OpKeyHashBinary:      {rt("hash32")},                                         // map.go:485
		OpKeyHashInterface:   {rt("hashmapInterfacePtrHash")},                        // map.go:493
		OpKeyEqualString:     {rt("stringEqual")},                                    // map.go:579
		OpKeyEqualBinary:     {rt("memequal")},                                       // map.go:611
		OpKeyEqualInterface:  {rt("hashmapInterfaceEqual")},                          // map.go:619
		OpStringConcat:       {rt("stringConcat")},                                   // compiler.go:3415
		OpStringEqual:        {rt("stringEqual")},                                    // compiler.go:3417
		OpStringLess:         {rt("stringLess")},                                     // compiler.go:3422
		OpStringFromUnicode:  {rt("stringFromUnicode")},                              // compiler.go:3742
		OpStringFromBytes:    {rt("stringFromBytes")},                                // compiler.go:3746
		OpStringFromRunes:    {rt("stringFromRunes")},                                // compiler.go:3748
		OpStringToBytes:      {rt("stringToBytes")},                                  // compiler.go:3901
		OpStringToRunes:      {rt("stringToRunes")},                                  // compiler.go:3903
		OpStringNext:         {rt("stringNext")},                                     // compiler.go:2900
		OpInterfaceEqual:     {rt("interfaceEqual")},                                 // compiler.go:3467
		OpTypeAssert:         {rt("typeAssert")},                                     // interface.go:1106
		OpTypeAssertPanic:    {rt("interfaceTypeAssert")},                            // interface.go:1194
		OpAppend:             {rt("sliceAppend")},                                    // compiler.go:1992
		OpPanic:              {rt("_panic")},                                         // compiler.go:1620, compiler.go:2200
		OpRecover:            {rt("_recover")},                                       // compiler.go:2282
		OpChanMake:           {rt("chanMake")},                                       // channel.go:28
		OpChanMakePanic:      {rt("chanMakePanic")},                                  // asserts.go:166
		OpChanSend:           {rt("chanSend")},                                       // channel.go:51
		OpChanRecv:           {rt("chanRecv")},                                       // channel.go:74
		OpChanClose:          {rt("chanClose")},                                      // channel.go:82
		OpChanLen:            {rt("chanLen")},                                        // compiler.go:2124
		OpChanCap:            {rt("chanCap")},                                        // compiler.go:2006
		OpChanSelect:         {rt("chanSelect")},                                     // channel.go:295, channel.go:306
		OpDeadlock:           {rt("deadlock")},                                       // channel.go:184
		OpGoStart:            {task("start")},                                        // goroutine.go:135
		OpGoExit:             {rt("exitGoroutine")},                                  // goroutine.go:324
		OpDeferSetup:         {rt("setupDeferFrame")},                                // defer.go:76
		OpDeferDestroy:       {rt("destroyDeferFrame")},                              // compiler.go:1624
		OpAlloc:              {rt("alloc")},                                          // gc.go:19
		OpAllocZero:          {rt("alloc_zero")},                                     // gc.go:27
		OpAllocNoHeap:        {rt("alloc_noheap")},                                   // gc.go:21
		OpLookupPanic:        {rt("lookupPanic")},                                    // asserts.go:34
		OpSlicePanic:         {rt("slicePanic")},                                     // asserts.go:85
		OpSliceToArrayPanic:  {rt("sliceToArrayPointerPanic")},                       // asserts.go:97
		OpUnsafeSlicePanic:   {rt("unsafeSlicePanic")},                               // asserts.go:129
		OpNilPanic:           {rt("nilPanic")},                                       // asserts.go:210
		OpNegativeShiftPanic: {rt("negativeShiftPanic")},                             // asserts.go:223
		OpDivideByZeroPanic:  {rt("divideByZeroPanic")},                              // asserts.go:236
		OpComplex64Div:       {rt("complex64div")},                                   // compiler.go:3382
		OpComplex128Div:      {rt("complex128div")},                                  // compiler.go:3384
		OpPrintLock:          {rt("printlock")},                                      // compiler.go:2203
		OpPrintUnlock:        {rt("printunlock")},                                    // compiler.go:2264
		OpPrintSpace:         {rt("printspace")},                                     // compiler.go:2206
		OpPrintNewline:       {rt("printnl")},                                        // compiler.go:2262
		OpPrintString:        {rt("printstring")},                                    // compiler.go:2213
		OpPrintPointer:       {rt("printptr")},                                       // compiler.go:2215, compiler.go:2218, compiler.go:2250
		OpPrintInt8:          {rt("printint8")},                                      // compiler.go:2222-2228
		OpPrintInt16:         {rt("printint16")},                                     // compiler.go:2222-2228
		OpPrintInt32:         {rt("printint32")},                                     // compiler.go:2222-2228
		OpPrintInt64:         {rt("printint64")},                                     // compiler.go:2222-2228
		OpPrintUint8:         {rt("printuint8")},                                     // compiler.go:2222-2228
		OpPrintUint16:        {rt("printuint16")},                                    // compiler.go:2222-2228
		OpPrintUint32:        {rt("printuint32")},                                    // compiler.go:2222-2228
		OpPrintUint64:        {rt("printuint64")},                                    // compiler.go:2222-2228
		OpPrintBool:          {rt("printbool")},                                      // compiler.go:2231
		OpPrintFloat32:       {rt("printfloat32")},                                   // compiler.go:2233
		OpPrintFloat64:       {rt("printfloat64")},                                   // compiler.go:2235
		OpPrintComplex64:     {rt("printcomplex64")},                                 // compiler.go:2237
		OpPrintComplex128:    {rt("printcomplex128")},                                // compiler.go:2239
		OpPrintInterface:     {rt("printitf")},                                       // compiler.go:2245
		OpPrintMap:           {rt("printmap")},                                       // compiler.go:2247
		OpPrintSlice:         {rt("printslice")},                                     // compiler.go:2256
		OpWasmExportCheckRun: {rt("wasmExportCheckRun")},                             // goroutine.go:191
		OpWasmExportRun:      {task("start"), rt("wasmExportRun")},                   // goroutine.go:268, goroutine.go:272
		OpWasmExportExit:     {rt("wasmExportExit")},                                 // goroutine.go:474
		OpArrayEqual:         {rt("memequal")},                                       // compiler.go:2618, compiler.go:3515
		OpChanTrySend:        {rt("chanTrySend")},                                    // channel.go:109
		OpChanTryRecv:        {rt("chanTryRecv")},                                    // channel.go:132
		OpUnwindCheck:        {rt("unwindPending")},                                  // calls.go:561
		OpUnwindClear:        {rt("clearUnwind")},                                    // defer.go:95, defer.go:752
		// OpStringFromBytesCompared and OpStringFromBytesComparedTo have none:
		// compiler.go:2679 compares the bytes in place.
		OpAsyncifyCatch: { // calls.go:178, calls.go:275, calls.go:316-357
			rt("unwindPending"), rt("asyncifyStopUnwindImport"), rt("savePanicReplay"),
			rt("panicRewindData"), rt("panicRewindStackPointer"), rt("setPanicRewindStackPointer"),
			rt("asyncifyStartRewindImport"),
		},
	},
	// symbol.go:348-355 names three entries by build mode. Only "default", the
	// mode tinygo build uses, is recorded: kanonarion models no build mode, so
	// the c-shared and wasi-legacy entries would be claims the record cannot back.
	wasm: []NamedExport{{Callee: rt("wasmEntryCommand"), Symbol: "_start"}}, // symbol.go:348
}
