/* Reached only through -I{root}/include: a preamble that includes it proves
   the target chain's {root} was replaced. */
#if FAKEBOARD != 1
#error the board's cflags did not reach clang
#endif
#define FAKE_HEADER_VALUE 3
