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
  expected instruction bits match the code at an address.
- `Matcher::resolve` adds the checks that need names. The caller implements
  `CodeInfo` (the targets of the instruction containing an address, and the name at an
  address). A module is rejected when its reference, or any site of a module of at most
  16 bytes, points at a differently named target. When several modules remain, each
  scores +4 per site whose target has the expected name and -4 per site whose target
  has another name; the highest score wins, and a tie is reported as ambiguous. When a
  required check has no name to compare yet, the result is `Delayed`.
- Not implemented: linker relaxation (used only by `glibc_riscv64.sig`), the ctype
  table check behind a `.` reference, and startup-signature references.

The CLI's `CodeInfo` reads names from the symbol tables and decodes only the operand
forms signatures point at: x86-64 32-bit relative displacements, i386 relative or
absolute operands, and AArch64 `b`/`bl`.

## Verification

- The parser reads all 212 signature files shipped with IDA 9.5 (versions 5, 6, 7, 9,
  10 and 11, about 4.7 million modules) to the last byte, and its output matches an
  independent Python reader on every file.
- On a static x86-64 test binary built against Gentoo glibc, `scan` with
  `glibc_amd64.sig`:

  | Input | Named, unambiguous matches | Name equals the symbol |
  |---|---|---|
  | Unstripped (names checked) | 180 | 174 |
  | Stripped (`.eh_frame` starts, names unknown) | 156 | 152 |

  The others are aliases of the same code (for example `free_mem` for
  `__intl_freemem`).
