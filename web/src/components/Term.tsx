// Plain-language glossary: <Term k="entropy">entropy</Term> shows a short
// explanation on hover (desktop) or tap (touch), so technical words never
// leave a non-expert stuck.
import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';

export const GLOSSARY: Record<string, string> = {
  entropy: 'How random the bytes look, from 0 to 8. Above about 7.2 usually means compressed or encrypted data, which can hide what a program does.',
  sha256: 'A fingerprint of the file. Any change to the file, even one letter, gives a completely different fingerprint. Used to look files up safely without sending them.',
  md5: 'An older, shorter file fingerprint. Still handy for searching, but not secure.',
  function: 'A small named piece of a program that does one job, like "check password" or "send message".',
  instruction: 'One basic step the processor carries out, like "add two numbers" or "jump to another place".',
  import: 'A ready-made function the program borrows from the operating system or a library, for example to open files or use the network. Imports hint at what a program can do.',
  export: 'A function this file offers to other programs.',
  string: 'A piece of readable text stored inside the file, such as a message, a web address or a file name.',
  section: 'A region of the file with one purpose: code, text, settings, and so on.',
  entitlement: 'A special permission a Mac app is given when it is signed, such as using the camera or the network. macOS enforces these.',
  signature: 'A digital seal from the maker. If it is valid, you know who made the file and that nobody changed it afterwards.',
  notarized: "Apple scanned this app for known malware before it was released. It's a good sign, though not a guarantee.",
  sandbox: 'A locked room for a program: it can only touch what it is explicitly allowed to.',
  hardening: 'Protections built into a program that make it harder for attackers to break.',
  aslr: 'Address randomisation: the program loads at a different place in memory each time, which makes attacks harder.',
  packed: 'The code is compressed or wrapped so it can only be read while running. Common in malware and copy protection.',
  stripped: 'The developer removed the human-readable names of functions, so Drishti shows generated names like sub_1000.',
  decompiler: 'A tool that turns machine code back into readable code that looks like C. The names are guesses, but the logic is real.',
  disassembly: "The program's machine code shown as individual processor instructions.",
  ioc: 'Indicator: a clue such as a web address, IP address or file path that can show where a program connects or what it touches.',
  yara: 'A pattern-matching tool that security researchers use to describe known malware.',
  capa: "A tool from Mandiant that recognises what a program can do from its code, such as 'records audio' or 'encrypts files'.",
  macro: 'A small program inside an Office document. Macros can be useful, but they are also a common way to spread malware.',
  sdk: "A ready-made kit from another company that an app includes, for example for analytics, ads or crash reports. It may send data to that company.",
  tracker: 'A kit that records how you use an app and sends it to a company, often for analytics or advertising.',
  cfg: 'Control-flow graph: a flow chart of one function showing which steps can follow which.',
  xref: 'Cross-reference: a place in the program that uses this address.',
  hash: 'A short fingerprint computed from the file contents.',
  electron: 'A framework that builds desktop apps from web technology (JavaScript). The app ships a copy of the Chrome browser engine.',
  persistence: 'Making sure a program starts again by itself, for example every time you log in.',
};

export function Term({ k, children }: { k: string; children: ComponentChildren }) {
  const [open, setOpen] = useState(false);
  const text = GLOSSARY[k];
  if (!text) return <>{children}</>;
  return (
    <span class={`term${open ? ' open' : ''}`} tabIndex={0} onClick={(e) => { e.stopPropagation(); setOpen(!open); }} onBlur={() => setOpen(false)} aria-label={`${typeof children === 'string' ? children : k}: ${text}`}>
      {children}
      <span class="term-tip" role="tooltip">{text}</span>
    </span>
  );
}
