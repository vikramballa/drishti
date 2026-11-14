// Plain-language hints for common instructions (shown as tooltips), so
// newcomers can read listings without a reference manual.
const X86: Record<string, string> = {
  mov: 'Copy a value from the second operand into the first', lea: 'Compute an address (or arithmetic) without reading memory', push: 'Put a value on the stack',
  pop: 'Take a value off the stack', call: 'Call a function; execution returns to the next instruction', ret: 'Return to the caller', jmp: 'Jump unconditionally',
  cmp: 'Compare two values (sets flags for the next conditional jump)', test: 'Bitwise AND just to set flags (often: is it zero?)', je: 'Jump if equal / zero', jne: 'Jump if not equal / not zero',
  jz: 'Jump if zero', jnz: 'Jump if not zero', ja: 'Jump if above (unsigned >)', jae: 'Jump if above or equal (unsigned ≥)', jb: 'Jump if below (unsigned <)', jbe: 'Jump if below or equal (unsigned ≤)',
  jg: 'Jump if greater (signed >)', jge: 'Jump if greater or equal (signed ≥)', jl: 'Jump if less (signed <)', jle: 'Jump if less or equal (signed ≤)', js: 'Jump if negative', jns: 'Jump if not negative',
  add: 'Add', sub: 'Subtract', imul: 'Signed multiply', mul: 'Unsigned multiply', idiv: 'Signed divide', div: 'Unsigned divide', inc: 'Add 1', dec: 'Subtract 1', neg: 'Negate',
  and: 'Bitwise AND', or: 'Bitwise OR', xor: 'Bitwise XOR (xor reg,reg sets it to 0)', not: 'Flip all bits', shl: 'Shift left (multiply by 2ⁿ)', shr: 'Logical shift right', sar: 'Arithmetic shift right (keeps sign)',
  movzx: 'Copy and zero-extend a smaller value', movsx: 'Copy and sign-extend a smaller value', movsxd: 'Copy a 32-bit value sign-extended to 64 bits', nop: 'Do nothing (padding)', int3: 'Breakpoint trap',
  endbr64: 'Marks a valid indirect-branch target (CET)', leave: 'Tear down the stack frame', cdqe: 'Sign-extend EAX into RAX', syscall: 'Enter the kernel (system call)', sete: 'Set byte to 1 if equal, else 0',
  setne: 'Set byte to 1 if not equal, else 0', cmove: 'Move only if equal', cmovne: 'Move only if not equal', ud2: 'Deliberate crash (unreachable code)', hlt: 'Halt',
};
const A64: Record<string, string> = {
  mov: 'Copy a value into a register', movz: 'Load a constant, clearing other bits', movk: 'Insert 16 bits into a register, keeping the rest', movn: 'Load the bitwise NOT of a constant',
  ldr: 'Load a value from memory into a register', str: 'Store a register into memory', ldp: 'Load two registers from memory', stp: 'Store two registers to memory (often saving them on the stack)',
  ldrb: 'Load one byte', strb: 'Store one byte', ldrh: 'Load 16 bits', strh: 'Store 16 bits', ldrsw: 'Load 32 bits and sign-extend', ldur: 'Load (unscaled offset)', stur: 'Store (unscaled offset)',
  adrp: 'Compute the 4 KB page address of a symbol (usually followed by add/ldr)', adr: 'Compute a nearby address', add: 'Add', sub: 'Subtract', mul: 'Multiply', udiv: 'Unsigned divide', sdiv: 'Signed divide',
  madd: 'Multiply then add', msub: 'Multiply then subtract (often: remainder)', and: 'Bitwise AND', orr: 'Bitwise OR', eor: 'Bitwise XOR', lsl: 'Shift left', lsr: 'Logical shift right', asr: 'Arithmetic shift right',
  cmp: 'Compare two values (sets flags)', cmn: 'Compare with negated value', tst: 'Bitwise AND just to set flags', subs: 'Subtract and set flags', adds: 'Add and set flags',
  b: 'Branch (jump) unconditionally', bl: 'Call a function (return address goes to x30)', blr: 'Call the function whose address is in a register', br: 'Jump to the address in a register',
  ret: 'Return to the caller (address in x30)', cbz: 'Branch if the register is zero', cbnz: 'Branch if the register is not zero', tbz: 'Branch if a specific bit is 0', tbnz: 'Branch if a specific bit is 1',
  'b.eq': 'Branch if equal', 'b.ne': 'Branch if not equal', 'b.hi': 'Branch if unsigned >', 'b.hs': 'Branch if unsigned ≥', 'b.lo': 'Branch if unsigned <', 'b.ls': 'Branch if unsigned ≤',
  'b.gt': 'Branch if signed >', 'b.ge': 'Branch if signed ≥', 'b.lt': 'Branch if signed <', 'b.le': 'Branch if signed ≤', 'b.mi': 'Branch if negative', 'b.pl': 'Branch if positive or zero',
  csel: 'Pick one of two registers depending on a condition', cset: 'Set register to 1 if the condition holds, else 0', csinc: 'Conditional select / increment', nop: 'Do nothing',
  pacibsp: 'Sign the return address (pointer authentication)', retab: 'Authenticate the return address, then return', autibsp: 'Authenticate the return address', braa: 'Authenticated jump via register',
  blraa: 'Authenticated call via register', brk: 'Breakpoint / deliberate trap', svc: 'System call', sxtw: 'Sign-extend 32 → 64 bits', uxtb: 'Zero-extend a byte', fmov: 'Copy a floating-point value',
  bti: 'Marks a valid indirect-branch target', udf: 'Undefined instruction (trap)', ubfx: 'Extract a bit field (unsigned)', sbfx: 'Extract a bit field (signed)', bfi: 'Insert a bit field',
};
export function mnemonicHelp(m: string, arch: string | undefined): string | undefined {
  const k = m.toLowerCase();
  return arch === 'aarch64' ? A64[k] : arch === 'x86' || arch === 'x86_64' ? X86[k] : A64[k] ?? X86[k];
}
