# Blackfin processor support for Ghidra

> **Fork note:** This is a derivative of [sualk/ghidra-blackfin](https://github.com/sualk/ghidra-blackfin)
> by Klaus Flittner. This fork adds **Blackfin+ (ADSP-BF70x) support**: full disassembly + p-code for
> the parallel DSP instruction set, ASTAT flags, 40-bit accumulators, and a BF702 boot-stream
> auto-detection heuristic in the loader. Original authorship and git history are preserved.
> See [Blackfin+ expansion](#blackfin-expansion-this-fork) below.

## Status

### Disassembly
All Blackfin instructions disassemble correctly. **Blackfin+ instructions are now implemented**
(parallel-issue DSP set, 32-bit immediate load/store/jump/call). Disassembly matches the GNU
binutils Blackfin+ decoder; encodings reserved/invalid in binutils (e.g. LSETUP rop=2) are rejected
identically.

Blackfin assembly syntax differs from most other assembly syntaxes in that it does not use mnenomics, but uses rather a mathematical syntax.

    R0 = R1 + R2
    [--SP] = R1

As ghidra more or less requires mnemonics in the disassembly, mneomics are added but the syntax after that is close to the blackfin assembly syntax.

    ADD  R0 = R1 + R2
    PUSH [--SP] = R1

### P-code
General-purpose and **DSP instructions are now implemented** (MAC/MULT, the parallel `^p` set —
shift/ALU/vector — and the misc ops: CC=A0 compares, TESTSET, DIVQ/DIVS, brev, EMUEXCPT). There are
**zero `unimpl` constructors**; functions no longer truncate with `halt_unimplemented()`.

ASTAT is broken into individual flag bits (AZ/AN/AC/AV/V/etc.); 40-bit accumulators and saturation
(s16/s32/s40, unsigned) are modelled. DSP semantics were transcribed from the GNU binutils Blackfin
simulator (`sim/bfin/bfin-sim.c`), not the PRM prose.

#### Known limitations (no halts — accuracy only)
1. **MAC modes:** the default signed-fractional mode is bit-exact. The other 8 `mmod` modes
   (integer/unsigned/w32/rounding) are approximate — the mode bits (iw0) and operands (iw1) sit in
   different instruction words, which SLEIGH cannot combine inside the multiply sub-piece.
2. **Parallel issue (`||`):** the 32-bit op and its two 16-bit slots run sequentially via a delay
   slot, so a register written by the 32-bit op and re-read by a 16-bit slot shows the new value;
   hardware would use the old value. SLEIGH cannot express simultaneous execution.

    R1 = R0 -|- R2 || [FP + 36] = R1 || NOP;
3. **Exotic SIMD ops** (byteop\*, vit_max, search, expadj, bitmux, extract/deposit, bxor, align,
   signbits, rot) are modelled as named p-code ops — explicit operation + data flow, internal
   bit-math not expanded.

    R1 = R0 -|- R2 || [FP + 36] = R1 || NOP;

`R1` is destination in the first instruction and source in the second instruction.
With the current implementation the second instruction uses the result from the first, but on real hardware it would use the unmodified value.

Hardware loops are only handled if the loop is initialized with an `LSETUP` instruction. Further the setup instruction and the end of the loop needs to be disassembled in one step.
Manually setting the loop registers is currently not handled.

### Loader
Supports loading of Blackfin boot streams (`.ldr` files).


## Installation
Use gradle to build extension: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle` and use Ghidra to install it: `File → Install Extensions...`

## Blackfin+ expansion (this fork)
Validated against real ADSP-BF70x (BF702) and BF59x (BF592) firmware boot streams: MAC-heavy
functions that previously decompiled to a bare `halt_unimplemented()` now produce full C; the BF702
boot entry, DDR/HW init, and parallel-issue code all decode. Semantics derive from the binutils
Blackfin+ toolchain fork (`opcodes/bfin-dis.c` for encodings, `sim/bfin/bfin-sim.c` for p-code).

Language variant `blackfin:LE:32:blackfin+` selects the Blackfin+ instruction set; the loader
auto-detects BF702 boot streams.

## Credits
Original Blackfin processor module: **Klaus Flittner** — https://github.com/sualk/ghidra-blackfin
Blackfin+ expansion: this fork.

## Links
* [Blackfin Processor Programming Reference (Rev. 2.2)](https://www.analog.com/media/en/dsp-documentation/processor-manuals/Blackfin_pgr_rev2.2.pdf)
* [Blackfin+ Processor Programming Reference (Rev. 1.0)](https://www.analog.com/media/en/dsp-documentation/processor-manuals/ADSP-BF70x_Blackfin_Programming_Reference.pdf)
* GNU binutils Blackfin+ toolchain (semantics source): https://github.com/deanm1278/blackfin-plus-gnu

