package tinylower

// v0430 is read off github.com/tinygo-org/tinygo@v0.43.0 compiler/; each entry
// names the line that emits the call. A name assembled from strings is cited at
// the line that assembles it.
//
// Not modelled, because each is a declaration with no body that a later TinyGo
// pass replaces, so an edge to it reaches nothing: internal/task.getGoroutineStackSize
// (goroutine.go:122), runtime.trackPointer (gc.go:111), and the per-interface
// $typeassert and $invoke functions (interface.go:1301) the compiler synthesises.
var v0430 = &Table{
	version:           "0.43.0",
	binOpFallsThrough: true,
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
		OpMapLen:             {rt("hashmapLen")},                                     // compiler.go:2095
		OpMapNext:            {rt("hashmapNext")},                                    // map.go:262
		OpKeyHashString:      {rt("hashmapStringPtrHash")},                           // map.go:455
		OpKeyHashFloat32:     {rt("hashmapFloat32Hash")},                             // map.go:460
		OpKeyHashFloat64:     {rt("hashmapFloat64Hash")},                             // map.go:462
		OpKeyHashBinary:      {rt("hash32")},                                         // map.go:485
		OpKeyHashInterface:   {rt("hashmapInterfacePtrHash")},                        // map.go:493
		OpKeyEqualString:     {rt("stringEqual")},                                    // map.go:579
		OpKeyEqualBinary:     {rt("memequal")},                                       // map.go:611
		OpKeyEqualInterface:  {rt("hashmapInterfaceEqual")},                          // map.go:619
		OpStringConcat:       {rt("stringConcat")},                                   // compiler.go:3369
		OpStringEqual:        {rt("stringEqual")},                                    // compiler.go:3371
		OpStringLess:         {rt("stringLess")},                                     // compiler.go:3376
		OpStringFromUnicode:  {rt("stringFromUnicode")},                              // compiler.go:3696
		OpStringFromBytes:    {rt("stringFromBytes")},                                // compiler.go:3700
		OpStringFromRunes:    {rt("stringFromRunes")},                                // compiler.go:3702
		OpStringToBytes:      {rt("stringToBytes")},                                  // compiler.go:3855
		OpStringToRunes:      {rt("stringToRunes")},                                  // compiler.go:3857
		OpStringNext:         {rt("stringNext")},                                     // compiler.go:2864
		OpInterfaceEqual:     {rt("interfaceEqual")},                                 // compiler.go:3421
		OpTypeAssert:         {rt("typeAssert")},                                     // interface.go:1107
		OpTypeAssertPanic:    {rt("interfaceTypeAssert")},                            // interface.go:1195
		OpAppend:             {rt("sliceAppend")},                                    // compiler.go:1961
		OpPanic:              {rt("_panic")},                                         // compiler.go:1613, compiler.go:2169
		OpRecover:            {rt("_recover")},                                       // compiler.go:2251
		OpChanMake:           {rt("chanMake")},                                       // channel.go:28
		OpChanMakePanic:      {rt("chanMakePanic")},                                  // asserts.go:158
		OpChanSend:           {rt("chanSend")},                                       // channel.go:51
		OpChanRecv:           {rt("chanRecv")},                                       // channel.go:74
		OpChanClose:          {rt("chanClose")},                                      // channel.go:82
		OpChanLen:            {rt("chanLen")},                                        // compiler.go:2093
		OpChanCap:            {rt("chanCap")},                                        // compiler.go:1975
		OpChanSelect:         {rt("chanSelect")},                                     // channel.go:295, channel.go:306
		OpDeadlock:           {rt("deadlock")},                                       // channel.go:184
		OpGoStart:            {task("start")},                                        // goroutine.go:132
		OpGoExit:             {rt("exitGoroutine")},                                  // goroutine.go:321
		OpDeferSetup:         {rt("setupDeferFrame")},                                // defer.go:76
		OpDeferDestroy:       {rt("destroyDeferFrame")},                              // compiler.go:1617
		OpAlloc:              {rt("alloc")},                                          // gc.go:19
		OpAllocZero:          {rt("alloc_zero")},                                     // gc.go:27
		OpAllocNoHeap:        {rt("alloc_noheap")},                                   // gc.go:21
		OpLookupPanic:        {rt("lookupPanic")},                                    // asserts.go:34
		OpSlicePanic:         {rt("slicePanic")},                                     // asserts.go:77
		OpSliceToArrayPanic:  {rt("sliceToArrayPointerPanic")},                       // asserts.go:89
		OpUnsafeSlicePanic:   {rt("unsafeSlicePanic")},                               // asserts.go:121
		OpNilPanic:           {rt("nilPanic")},                                       // asserts.go:202
		OpNegativeShiftPanic: {rt("negativeShiftPanic")},                             // asserts.go:215
		OpDivideByZeroPanic:  {rt("divideByZeroPanic")},                              // asserts.go:228
		OpComplex64Div:       {rt("complex64div")},                                   // compiler.go:3336
		OpComplex128Div:      {rt("complex128div")},                                  // compiler.go:3338
		OpPrintLock:          {rt("printlock")},                                      // compiler.go:2172
		OpPrintUnlock:        {rt("printunlock")},                                    // compiler.go:2233
		OpPrintSpace:         {rt("printspace")},                                     // compiler.go:2175
		OpPrintNewline:       {rt("printnl")},                                        // compiler.go:2231
		OpPrintString:        {rt("printstring")},                                    // compiler.go:2182
		OpPrintPointer:       {rt("printptr")},                                       // compiler.go:2184, compiler.go:2187, compiler.go:2219
		OpPrintInt8:          {rt("printint8")},                                      // compiler.go:2191-2197
		OpPrintInt16:         {rt("printint16")},                                     // compiler.go:2191-2197
		OpPrintInt32:         {rt("printint32")},                                     // compiler.go:2191-2197
		OpPrintInt64:         {rt("printint64")},                                     // compiler.go:2191-2197
		OpPrintUint8:         {rt("printuint8")},                                     // compiler.go:2191-2197
		OpPrintUint16:        {rt("printuint16")},                                    // compiler.go:2191-2197
		OpPrintUint32:        {rt("printuint32")},                                    // compiler.go:2191-2197
		OpPrintUint64:        {rt("printuint64")},                                    // compiler.go:2191-2197
		OpPrintBool:          {rt("printbool")},                                      // compiler.go:2200
		OpPrintFloat32:       {rt("printfloat32")},                                   // compiler.go:2202
		OpPrintFloat64:       {rt("printfloat64")},                                   // compiler.go:2204
		OpPrintComplex64:     {rt("printcomplex64")},                                 // compiler.go:2206
		OpPrintComplex128:    {rt("printcomplex128")},                                // compiler.go:2208
		OpPrintInterface:     {rt("printitf")},                                       // compiler.go:2214
		OpPrintMap:           {rt("printmap")},                                       // compiler.go:2216
		OpPrintSlice:         {rt("printslice")},                                     // compiler.go:2225
		OpWasmExportCheckRun: {rt("wasmExportCheckRun")},                             // goroutine.go:188
		OpWasmExportRun:      {task("start"), rt("wasmExportRun")},                   // goroutine.go:265, goroutine.go:269
		OpWasmExportExit:     {rt("wasmExportExit")},                                 // goroutine.go:471
		OpArrayEqual:         {rt("memequal")},                                       // compiler.go:2587, compiler.go:3469
		OpChanTrySend:        {rt("chanTrySend")},                                    // channel.go:109
		OpChanTryRecv:        {rt("chanTryRecv")},                                    // channel.go:132
		OpUnwindCheck:        {rt("unwindPending")},                                  // calls.go:560
		OpUnwindClear:        {rt("clearUnwind")},                                    // defer.go:95, defer.go:752
		OpAsyncifyCatch: { // calls.go:178, calls.go:275, calls.go:316-357
			rt("unwindPending"), rt("asyncifyStopUnwindImport"), rt("savePanicReplay"),
			rt("panicRewindData"), rt("panicRewindStackPointer"), rt("setPanicRewindStackPointer"),
			rt("asyncifyStartRewindImport"),
		},
		OpStringFromBytesCompared: {rt("stringFromBytes")}, // compiler.go:3700
		// OpStringFromBytesComparedTo has none: compiler.go:2643 compares the bytes in place.
	},
	// symbol.go:342-354 names three entries by build mode. Only "default", the
	// mode tinygo build uses, is recorded: kanonarion models no build mode, so
	// the c-shared and wasi-legacy entries would be claims the record cannot back.
	wasm: []NamedExport{{Callee: rt("wasmEntryCommand"), Symbol: "_start"}}, // symbol.go:347
}
