package tinylower

// v0420 is read off github.com/tinygo-org/tinygo@v0.42.0 compiler/; each entry
// names the line that emits the call. A name assembled from strings is cited at
// the line that assembles it.
//
// Not modelled, because each is a declaration with no body that a later TinyGo
// pass replaces, so an edge to it reaches nothing: internal/task.getGoroutineStackSize
// (goroutine.go:116), runtime.trackPointer (gc.go:111), and the per-interface
// $typeassert and $invoke functions (interface.go:1274) the compiler synthesises.
var v0420 = &Table{
	version: "0.42.0",
	callees: map[Op][]Callee{
		OpMapMake:            {rt("hashmapMakeGeneric")},                             // map.go:55
		OpMapKeyFuncsString:  {rt("hashmapStringPtrHash"), rt("hashmapStringEqual")}, // map.go:43, map.go:44
		OpMapKeyFuncsBinary:  {rt("hash32"), rt("memequal")},                         // map.go:46, map.go:47
		OpMapGetString:       {rt("hashmapStringGet")},                               // map.go:99
		OpMapGetBinary:       {rt("hashmapBinaryGet")},                               // map.go:105
		OpMapGetGeneric:      {rt("hashmapGenericGet")},                              // map.go:107
		OpMapSetString:       {rt("hashmapStringSet")},                               // map.go:125
		OpMapSetBinary:       {rt("hashmapBinarySet")},                               // map.go:129
		OpMapSetGeneric:      {rt("hashmapGenericSet")},                              // map.go:131
		OpMapDeleteString:    {rt("hashmapStringDelete")},                            // map.go:147
		OpMapDeleteBinary:    {rt("hashmapBinaryDelete")},                            // map.go:153
		OpMapDeleteGeneric:   {rt("hashmapGenericDelete")},                           // map.go:155
		OpMapClear:           {rt("hashmapClear")},                                   // map.go:166
		OpMapLen:             {rt("hashmapLen")},                                     // compiler.go:1983
		OpMapNext:            {rt("hashmapNext")},                                    // map.go:185
		OpKeyHashString:      {rt("hashmapStringPtrHash")},                           // map.go:379
		OpKeyHashFloat32:     {rt("hashmapFloat32Hash")},                             // map.go:384
		OpKeyHashFloat64:     {rt("hashmapFloat64Hash")},                             // map.go:386
		OpKeyHashBinary:      {rt("hash32")},                                         // map.go:409
		OpKeyHashInterface:   {rt("hashmapInterfacePtrHash")},                        // map.go:417
		OpKeyEqualString:     {rt("stringEqual")},                                    // map.go:503
		OpKeyEqualBinary:     {rt("memequal")},                                       // map.go:535
		OpKeyEqualInterface:  {rt("hashmapInterfaceEqual")},                          // map.go:543
		OpStringConcat:       {rt("stringConcat")},                                   // compiler.go:3182
		OpStringEqual:        {rt("stringEqual")},                                    // compiler.go:3184
		OpStringLess:         {rt("stringLess")},                                     // compiler.go:3189
		OpStringFromUnicode:  {rt("stringFromUnicode")},                              // compiler.go:3497
		OpStringFromBytes:    {rt("stringFromBytes")},                                // compiler.go:3501
		OpStringFromRunes:    {rt("stringFromRunes")},                                // compiler.go:3503
		OpStringToBytes:      {rt("stringToBytes")},                                  // compiler.go:3656
		OpStringToRunes:      {rt("stringToRunes")},                                  // compiler.go:3658
		OpStringNext:         {rt("stringNext")},                                     // compiler.go:2713
		OpInterfaceEqual:     {rt("interfaceEqual")},                                 // compiler.go:3234
		OpTypeAssert:         {rt("typeAssert")},                                     // interface.go:1082
		OpTypeAssertPanic:    {rt("interfaceTypeAssert")},                            // interface.go:1169
		OpAppend:             {rt("sliceAppend")},                                    // compiler.go:1849
		OpPanic:              {rt("_panic")},                                         // compiler.go:1574, compiler.go:2057
		OpRecover:            {rt("_recover")},                                       // compiler.go:2139
		OpChanMake:           {rt("chanMake")},                                       // channel.go:26
		OpChanMakePanic:      {rt("chanMakePanic")},                                  // asserts.go:158
		OpChanSend:           {rt("chanSend")},                                       // channel.go:49
		OpChanRecv:           {rt("chanRecv")},                                       // channel.go:72
		OpChanClose:          {rt("chanClose")},                                      // channel.go:80
		OpChanLen:            {rt("chanLen")},                                        // compiler.go:1981
		OpChanCap:            {rt("chanCap")},                                        // compiler.go:1863
		OpChanSelect:         {rt("chanSelect")},                                     // channel.go:199, channel.go:210
		OpDeadlock:           {rt("deadlock")},                                       // channel.go:92
		OpGoStart:            {task("start")},                                        // goroutine.go:126
		OpGoExit:             {rt("exitGoroutine")},                                  // goroutine.go:315
		OpDeferSetup:         {rt("setupDeferFrame")},                                // defer.go:79
		OpDeferDestroy:       {rt("destroyDeferFrame")},                              // compiler.go:1578
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
		OpComplex64Div:       {rt("complex64div")},                                   // compiler.go:3149
		OpComplex128Div:      {rt("complex128div")},                                  // compiler.go:3151
		OpPrintLock:          {rt("printlock")},                                      // compiler.go:2060
		OpPrintUnlock:        {rt("printunlock")},                                    // compiler.go:2121
		OpPrintSpace:         {rt("printspace")},                                     // compiler.go:2063
		OpPrintNewline:       {rt("printnl")},                                        // compiler.go:2119
		OpPrintString:        {rt("printstring")},                                    // compiler.go:2070
		OpPrintPointer:       {rt("printptr")},                                       // compiler.go:2072, compiler.go:2075, compiler.go:2107
		OpPrintInt8:          {rt("printint8")},                                      // compiler.go:2079-2085
		OpPrintInt16:         {rt("printint16")},                                     // compiler.go:2079-2085
		OpPrintInt32:         {rt("printint32")},                                     // compiler.go:2079-2085
		OpPrintInt64:         {rt("printint64")},                                     // compiler.go:2079-2085
		OpPrintUint8:         {rt("printuint8")},                                     // compiler.go:2079-2085
		OpPrintUint16:        {rt("printuint16")},                                    // compiler.go:2079-2085
		OpPrintUint32:        {rt("printuint32")},                                    // compiler.go:2079-2085
		OpPrintUint64:        {rt("printuint64")},                                    // compiler.go:2079-2085
		OpPrintBool:          {rt("printbool")},                                      // compiler.go:2088
		OpPrintFloat32:       {rt("printfloat32")},                                   // compiler.go:2090
		OpPrintFloat64:       {rt("printfloat64")},                                   // compiler.go:2092
		OpPrintComplex64:     {rt("printcomplex64")},                                 // compiler.go:2094
		OpPrintComplex128:    {rt("printcomplex128")},                                // compiler.go:2096
		OpPrintInterface:     {rt("printitf")},                                       // compiler.go:2102
		OpPrintMap:           {rt("printmap")},                                       // compiler.go:2104
		OpPrintSlice:         {rt("printslice")},                                     // compiler.go:2113
		OpWasmExportCheckRun: {rt("wasmExportCheckRun")},                             // goroutine.go:182
		OpWasmExportRun:      {task("start"), rt("wasmExportRun")},                   // goroutine.go:259, goroutine.go:263
		OpWasmExportExit:     {rt("wasmExportExit")},                                 // goroutine.go:465
	},
	// symbol.go:338-350 names three entries by build mode. Only "default", the
	// mode tinygo build uses, is recorded: kanonarion models no build mode, so
	// the c-shared and wasi-legacy entries would be claims the record cannot back.
	wasm: []NamedExport{{Callee: rt("wasmEntryCommand"), Symbol: "_start"}}, // symbol.go:343
}
