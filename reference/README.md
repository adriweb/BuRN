# CrASH 1.6 reference

This is the archive from https://www.ticalc.org/archives/files/fileinfo/87/8772.html

`CRASH.82B` is the stock CrASH 1.6 TI-82 backup used as the structural
template for BuRN:

```text
SHA-256  99d891b7e7d9c088476e3218c5d7f53202c76b745d01c6725472ba68850bb541
Size     3416 bytes
```

It supplies the original BASIC parser prefix and the unaffected restored-memory
regions. The build does not copy it blindly: `tools/mk82b.c` parses the
container, validates the signature, lengths, checksum, shell layout, parser
prefix, `pTemp`, fake-matrix pointer, removable tail, and VAT entry before
constructing a new backup.

The native shell body, ROM-specific call behavior, parser changes, VAT name,
lengths, and final checksum are produced by this repository. No TI ROM dump is
included or required.

CrASH is and remains the work of Hideaki Omuro and Jeff Mears.  
Even though it is nowadays considered abandonware, its own [CRASH.TXT](CRASH.TXT)
permits redistribution of the CrASH 1.6 archive ("the complete runtime package")
only while all files remain intact and unmodified. So here they are, as-is.  
Note however that the BuRN build uses only `CRASH.82B`.
