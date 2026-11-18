# BuRN for the TI-82

BuRN is a clean-room, CrASH-compatible shell for TI-82 ROMs 15.0 through
19.006. It runs raw OS-82, classic CrASH, and standard Ash 3.0 programs while
preserving the public CrASH entry points.

Compared with CrASH, BuRN lets a program opt into free user RAM through its
header. A zero `policy` byte keeps the usual CrASH/Ash occupied-RAM context;
any nonzero value provides free RAM and returns to TI-OS afterward. BuRN also
adapts the known relocated ROM calls used by compatible programs on ROM
19.006.

Self-loading Ash programs, which use a different BASIC loader format, are not
supported.

## ROM 19.006 limitations

- Programs return to TI-OS rather than directly to the BuRN menu.
- Up/Down reaches the full program list, but Left/Right page shortcuts are not
  available.
- Ash compatibility translates known `ROM_CALL`s and unconditional direct
  `CALL`s; conditional direct calls are not translated.

## Ready-to-transfer installers

"Hacked backup" files are provided for each version [in the releases](https://github.com/adriweb/BuRN/releases/latest).

| Calculator ROM | Installer |
| --- | --- |
| 15.0, 16.0, 17.0 or 18.0 | [`BURN-15.0-16.0-17.0-18.0.82B`](https://github.com/adriweb/BuRN/releases/latest/download/BURN-15.0-16.0-17.0-18.0.82B) |
| 19.0 | [`BURN-19.0.82B`](https://github.com/adriweb/BuRN/releases/latest/download/BURN-19.0.82B) |
| 19.006 | [`BURN-19.006.82B`](https://github.com/adriweb/BuRN/releases/latest/download/BURN-19.006.82B) |

After restoring the backup with TI GRAPHLINK, TILP, or [WebTILP](https://web.tilp.info) for instance, launch `prgmBURN`.

## Build

Requirements:

- GNU Make
- GNU Z80 binutils with `z80-none-elf-*` (`as`, `ld`, `objcopy`) on `PATH`  
  (the ones used by the CE toolchain work fine - [see here](https://github.com/CE-Programming/binutils-gdb/releases/nightly))
- a C99 compiler available as `cc`

Build all three installers (the generated files are written to `build/release/`):

```sh
make
```

For a toolchain installed outside `PATH`, either set the cross prefix:

```sh
make CROSS_PREFIX=/opt/z80/bin/z80-none-elf-
```

or set the individual tools:

```sh
make AS=/opt/z80/bin/z80-none-elf-as \
     LD=/opt/z80/bin/z80-none-elf-ld \
     OBJCOPY=/opt/z80/bin/z80-none-elf-objcopy
```

`CC`, `ASFLAGS`, `CFLAGS`, `LDFLAGS`, and `BUILD_DIR` are also overrideable.

## How the build works

1. GNU `as` assembles [`src/burn.s`](src/burn.s) with one of three ROM profiles.
2. GNU `ld` applies [`src/burn.ld`](src/burn.ld), fixes the public CrASH ABI
   addresses, and requires the native body to occupy exactly `$8D4E..$90FE`.
3. [`tools/mk82b.c`](tools/mk82b.c) parses the CrASH template, replaces the shell and parser-specific fields, and rebuilds the lengths and checksum.

The stock backup is the only opaque build input. Its purpose and identity are
documented in [`reference/README.md`](reference/README.md).

## Validation

On TilEm, tests passed against the six TI-82 ROMs: 15.0, 16.0, 17.0, 18.0, 19.0, and 19.006:

- static direct-write auditing;
- parser entry, catalog filtering, paging through 19.0, complete Up/Down
  traversal on 19.006, and repeat entry;
- short, exact-14-character, and cropped long catalog comments;
- interrupt-driven catalog idling with APD inhibited only while the menu waits;
- a restored `prgmBURN` last-entry token with the parser's RAM geometry unchanged;
- dedicated header-policy diagnostics on all six ROMs proving zero free RAM
  for zero-policy CrASH/Ash programs, nonzero `OPS-FPS+1` free RAM for
  nonzero-policy programs, stable values across repeat launches, and forced
  shell exit for the latter;
- safe mixed-policy sequencing: ROMs 15.0 through 19.0 refuse a zero-policy
  launch while a previously relocated allocation still owns `$90FF`, while
  ROM 19.006 exits after every classic/Ash target and reconstructs normal
  allocator state when BuRN is reopened;
- MARIO2 on ROMs 19.0 and 19.006 through two complete
  `_CloseProg`/recreate/return cycles, another launch after leaving and
  reopening BuRN, preserved NAGEL data, and a post-test native `1+1=2` without
  a RAM clear;
- raw, classic CrASH, and standard Ash 3.0 program layouts, including bounded
  Ash names and inline `ROM_CALL`; target `RET` returns to the BuRN menu
  through ROM 19.0 and directly to TI-OS on ROM 19.006;
- normal `RET` and profile-native forced-home exits without a RAM clear;
- a clean saved home screen and a home-positioned cursor after every
  BuRN-owned exit;
- the original Fast Tunnel through natural loss, score dismissal, stale-buffer
  confirmation, relaunch, a clean second game, a non-pinned two-direction
  tunnel path, and a clean second exit;
- the CrASH public state (`APD_FREE=$0300`, `INT_STATE=0`, `CRASH_VER=$16`),
  classic launch state, `ROM_CALL`, `EXIT_2_TIOS`, `RAND`, `CP_HL_BC`,
  `CR_KHAND`, and `CR_GRBCopy` contracts;
- all 30 documented CrASH, SNG, and Ash 3.0 ROM 19.006 `ROM_CALL`
  translations, plus Ash's four relocated unconditional direct-call operands,
  unchanged conditional calls, and unchanged control addresses;
- a 4,101-byte relocation stress case;
- VAT preservation and a post-test `1+1=2`;

One harmless implementation difference remains: original CrASH used
`TEXT_MEM2` as relocation scratch inside `CR_KHAND`, destroying its contents.
BuRN does not need that workaround because the running program remains inside a
live TI-OS allocation, so it preserves `TEXT_MEM2` while still resetting the
documented keyboard-scan flag. CrASH's own SDK classifies `TEXT_MEM2` as
destroyed by `CR_KHAND`, so conforming programs cannot depend on the old
destructive side effect.
