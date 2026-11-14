# Drishti IR (`drishti-ir`)

Status: **B1 done** (2026-11-12) — IR types, pretty-printer and reference
interpreter. B2 (AArch64 / x86-64 lifters) and B3 (Unicorn differential tests)
are next. Spec: `PROJECT_SPEC.md` §7.4.

The IR is a small, typed, P-code-like language. Every value has a bit width.
It exists so analysis (SSA, dataflow, dead-flag elimination, emulation) and the
decompiler can reason about one normalised instruction set instead of two
machine ISAs.

## Varnodes (`Var`)

A varnode is a typed storage location:

| Variant | Meaning |
|---|---|
| `Reg { name, width }` | a named machine register or flag (`rax:64`, `ZF:1`) |
| `Temp { id, width }` | a lifter-local temporary (`t3:64`) |
| `Const { value, width }` | a constant (`0x8:64`) |
| `Mem { addr, width }` | a little-endian memory cell at the address the `addr` varnode evaluates to |

Widths are in bits. Flags are 1-bit registers (`CF`, `ZF`, `SF`, `OF`, `PF`,
`AF`) — the lifter models them explicitly; dead-flag elimination happens later
in analysis, not in the lifter.

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
| Other | `Intrinsic(name, ins, out)`, `Undef` |

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

`State` holds registers/flags (by name) and byte-addressed little-endian
memory. `State::exec(&Insn) -> Result<Step, StepError>` executes one operation
and returns a control-flow `Step` (`Next`, `Branch`, `NotTaken`, `Call`,
`Indirect`, `Return`). It is deterministic and host-independent, so it is the
oracle the lifter's differential tests (B3) will compare against: run the
original bytes in Unicorn and the lifted IR here from the same random initial
state, and require registers, flags and memory to match.

## What comes next

- **B2** — AArch64 lifter first (the dev platform), then the x86-64 integer
  subset; everything else lifts to `Intrinsic` with a warning.
- **B3** — `proptest`-driven differential tests against Unicorn.
- **B4+** — SSA, dominators, dataflow, type recovery, structuring — all consume
  this IR. The vulnerability auditor (`drishti-disasm::vuln`) will upgrade from
  call-graph reachability to value-level taint once the lifter and dataflow land.
