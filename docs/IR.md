# Drishti IR (`drishti-ir`)

Status: **B1 done** (2026-11-12) — IR types, pretty-printer and reference
interpreter; shrunk on 2026-11-15 (Day 2) before the lifter. **B2 AArch64 +
B3 done** (2026-11-15, Days 6–12): `a64.rs` lifter (97.99% of Telegram's
instructions get full semantics), checked against Unicorn by
`crates/drishti-difftest` (`make difftest`). x86-64 lifter not started.
Spec: `PROJECT_SPEC.md` §7.4.

The IR is a small, typed, P-code-like language. Every value has a bit width.
It exists so analysis (SSA, dataflow, dead-flag elimination, emulation) and the
decompiler can reason about one normalised instruction set instead of two
machine ISAs.

## Varnodes (`Var`) and destinations (`Place`)

A `Var` is a value an operation reads:

| Variant | Meaning |
|---|---|
| `Reg { id, width }` | a machine register or flag (`x0:64`, `ZF:1`); a smaller width reads the low bits (`x0:32` is `w0`) |
| `Temp { id, width }` | a lifter-local temporary (`t3:64`) |
| `Const { value, width }` | a constant up to 64 bits (`0x8:64`) |
| `Wide { value, width }` | a boxed constant wider than 64 bits (rare: vector immediates) |

A `Place` is where an operation writes: `Reg { id, width }` or `Temp { id, width }`.
Constants are not destinations (the type system rules it out) and memory is
reached only through `Load` / `Store`. Writing a register with a smaller width
zero-extends into the full register (AArch64 `W` and scalar-FP writes, x86-64
32-bit writes); writes that keep the upper bits (x86 `ax`/`al`) are lifted
explicitly as `Extract` + `Concat`.

Widths are in bits. Flags are 1-bit registers (AArch64 `N Z C V`; x86-64 `CF`,
`PF`, `AF`, `ZF`, `SF`, `DF`, `OF`) — the lifter models them explicitly;
dead-flag elimination happens later in analysis, not in the lifter.

### Registers (`RegId`)

A `RegId` is a `u16`: the high byte picks the architecture, the low byte
indexes that architecture's table (`Arch::regs()`, `Arch::reg("x0")`,
`RegId::name()`, `RegId::width()`). Only full architectural registers are in
the tables; there is no zero register (`xzr` reads lift to the constant 0).

| Arch | Table |
|---|---|
| `Aarch64` | `x0`–`x30`, `sp`, `pc`, `N Z C V`, `v0`–`v31` (128), `fpcr`, `fpsr`, `tpidr_el0` |
| `X86_64` | `rax`…`r15` (encoding order), `rip`, `CF PF AF ZF SF DF OF`, `xmm0`–`xmm15` (128), `fs_base`, `gs_base` |

### Size budget

Checked by the `sizes` unit test: `Var` 16 B, `Place` 8 B, `Op` 48 B, `Insn`
56 B, with no heap use except wide constants and `Intrinsic` (boxed). Before
Day 2 (2026-11-15) `Var` was 32 B and `Insn` 128 B, plus a heap `String` per
register mention and a `Box` per memory varnode.

## Operations (`Op`)

Each `Op` has at most one destination, which fixes the result width.

| Group | Ops |
|---|---|
| Data movement | `Copy`, `Load`, `Store` |
| Integer arithmetic | `Bin(Add/Sub/Mul/Udiv/Sdiv/Urem/Srem)`, `Un(Neg)` |
| Bitwise | `Bin(And/Or/Xor/Shl/Lshr/Ashr)`, `Un(Not/Popcount)` |
| Width changes | `Zext`, `Sext`, `Trunc`, `Concat`, `Extract(lo,hi)` |
| Comparison (→ width 1) | `Bin(Eq/Ne/Ult/Ule/Slt/Sle)` |
| Flag helpers (→ width 1) | `Bin(Carry/Scarry/Sborrow)` |
| Control flow | `Branch`, `CBranch`, `BranchInd`, `Call`, `CallInd`, `Return` |
| Other | `Intrinsic(Box<{name, ins, out}>)`, `Undef` |

`Insn { addr, op }` tags each operation with the machine address it was lifted
from, so one machine instruction becomes a sequence of address-tagged `Insn`s.

### Semantics notes

- All arithmetic is two's-complement and wraps; results are masked to the
  destination width.
- Signed ops (`Sdiv`, `Srem`, `Slt`, `Sle`, `Ashr`, `Sext`) interpret inputs as
  signed values sign-extended from their own width.
- `Carry(a,b)` = unsigned overflow of `a+b`; `Scarry(a,b)` / `Sborrow(a,b)` =
  signed overflow of `a+b` / `a-b`. These match SLEIGH/P-code `INT_CARRY`,
  `INT_SCARRY`, `INT_SBORROW`.
- Shift amounts are not truncated: a shift by ≥ the width gives 0 (`Ashr`:
  the sign fill).
- Division/remainder by zero yields 0 (the lifter is expected to guard real
  divide traps separately).
- `Concat(hi, lo)` = `(hi << width(lo)) | lo`. `Extract(a, lo, hi)` = bits
  `[lo, hi)` of `a`.

## Pretty-printer

`render(&[Insn]) -> String` prints one operation per line, address-tagged:

```
0x00001000: t0:64 = rax:64
0x00001000: rax:64 = ADD t0:64, 0x8:64
0x00001004: ZF:1 = EQ rax:64, 0x0:64
0x00001004: CBRANCH ZF:1, 0x1020
```

## Reference interpreter

`State` holds registers/flags (by `RegId`), temporaries and byte-addressed
little-endian memory; anything never written reads as zero. `State::exec(&Insn) -> Result<Step, StepError>` executes one operation
and returns a control-flow `Step` (`Next`, `Branch`, `NotTaken`, `Call`,
`Indirect`, `Return`). It is deterministic and host-independent, so it is the
oracle the lifter's differential tests (B3) will compare against: run the
original bytes in Unicorn and the lifted IR here from the same random initial
state, and require registers, flags and memory to match.

## What comes next

- **B2** — AArch64 done (`a64.rs`; FP/SIMD arithmetic and crypto are
  `INTRINSIC a64.<class>`). Next: the x86-64 integer subset.
- **B3** — done for AArch64: one instruction from a random state in Unicorn
  and in this interpreter, compare X/SP/NZCV/V, memory and next PC
  (`crates/drishti-difftest`, DECISIONS #58).
- **B4+** — SSA, dominators, dataflow, type recovery, structuring — all consume
  this IR. The vulnerability auditor (`drishti-disasm::vuln`) will upgrade from
  call-graph reachability to value-level taint once the lifter and dataflow land.
