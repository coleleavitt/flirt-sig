# flirt-sig

Reader and matcher for IDA FLIRT `.sig` signature files, format versions 5 to 11.

```
flirt-sig dump <file.sig> [N|all]
flirt-sig scan <file.sig> <binary> [--sweep]
```

`dump` prints the header, the module count and the first N modules (default 5).

`scan` matches the signature against the executable sections of an ELF, PE or Mach-O
file and prints `address name` for each public of each matching module. It tries the
function starts it can find: function symbols, ELF `.eh_frame` FDEs and PE `.pdata`
entries, so stripped ELF and PE files work. `--sweep` tries every byte offset instead,
which also matches inside functions and is much noisier.

## Library

- `Signature::parse` reads a whole file into a header and a list of modules.
- `Matcher::match_at` returns the modules whose pattern, CRC-16, tail bytes and
  expected instruction bits match the code at an address. Referenced names and site
  names are not checked, because that needs the names of the code the match calls.
  Linker relaxation is not modelled.

## Verification

- The parser reads all 212 signature files shipped with IDA 9.5 (versions 5, 6, 7, 9,
  10 and 11, about 4.7 million modules) to the last byte, and its output matches an
  independent Python reader on every file.
- On a static x86-64 test binary built against Gentoo glibc, `scan` with
  `glibc_amd64.sig` gave the same result with and without symbols: 160 named,
  unambiguous matches, 151 of them with the name the symbol table has. Most of the
  rest are aliases of the same code.
