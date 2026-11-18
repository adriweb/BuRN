SECTIONS
{
  . = 0x8D4E;
  .text : { *(.text) }
  /DISCARD/ : { *(.comment) *(.note*) }
}
ASSERT(SIZEOF(.text) == 0x90FF - 0x8D4E, "BuRN binary has wrong size")
