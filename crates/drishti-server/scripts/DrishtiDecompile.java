// Drishti: decompile functions at given addresses and write JSON.
// Args: <out.json> <drishti-image-base-hex> <addr-hex>...
// Addresses are Drishti virtual addresses; they are shifted by the
// difference between Ghidra's image base and Drishti's.
//@category Drishti
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class DrishtiDecompile extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) { println("usage: out.json base addr..."); return; }
        long ourBase = Long.parseUnsignedLong(args[1], 16);
        long delta = currentProgram.getImageBase().getOffset() - ourBase;
        DecompInterface d = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        d.setOptions(opts);
        d.toggleCCode(true);
        d.toggleSyntaxTree(false);
        d.setSimplificationStyle("decompile");
        if (!d.openProgram(currentProgram)) { throw new Exception("decompiler failed to start: " + d.getLastMessage()); }
        StringBuilder out = new StringBuilder("{\"image_base\":" + esc(currentProgram.getImageBase().toString()) + ",\"functions\":[");
        for (int i = 2; i < args.length; i++) {
            if (i > 2) out.append(',');
            long va = Long.parseUnsignedLong(args[i], 16);
            out.append("{\"addr\":").append(esc(args[i]));
            try {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va + delta);
                Function f = getFunctionAt(a);
                if (f == null) {
                    disassemble(a);
                    f = createFunction(a, null);
                }
                if (f == null) { out.append(",\"error\":\"Ghidra could not create a function here\"}"); continue; }
                DecompileResults r = d.decompileFunction(f, 90, monitor);
                if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) {
                    out.append(",\"error\":").append(esc(r == null ? "no result" : r.getErrorMessage())).append('}');
                    continue;
                }
                out.append(",\"name\":").append(esc(f.getName()));
                out.append(",\"signature\":").append(esc(r.getDecompiledFunction().getSignature()));
                out.append(",\"code\":").append(esc(r.getDecompiledFunction().getC())).append('}');
            } catch (Exception e) {
                out.append(",\"error\":").append(esc(e.toString())).append('}');
            }
        }
        out.append("]}");
        d.dispose();
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            w.write(out.toString());
        }
    }
}
