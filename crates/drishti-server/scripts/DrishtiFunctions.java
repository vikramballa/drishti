// Drishti: export every function Ghidra found (entry, extent, basic
// blocks, direct callees) as JSON, for the engine comparison.
// Args: <out.json> <drishti-image-base-hex>
// Addresses are written as Drishti virtual addresses (shifted by the
// difference between Ghidra's image base and Drishti's).
//@category Drishti
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class DrishtiFunctions extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
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
        if (args.length < 2) { println("usage: out.json base"); return; }
        long ourBase = Long.parseUnsignedLong(args[1], 16);
        long delta = currentProgram.getImageBase().getOffset() - ourBase;
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        StringBuilder out = new StringBuilder("{\"image_base\":" + esc(currentProgram.getImageBase().toString()) + ",\"functions\":[");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        boolean first = true;
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            if (f.isExternal()) continue;
            Address entry = f.getEntryPoint();
            if (!entry.isMemoryAddress()) continue;
            AddressSetView body = f.getBody();
            long size = body.isEmpty() ? 0 : body.getMaxAddress().getOffset() - entry.getOffset() + 1;
            int blocks = 0;
            CodeBlockIterator bi = bbm.getCodeBlocksContaining(body, monitor);
            while (bi.hasNext()) { bi.next(); blocks++; }
            if (!first) out.append(',');
            first = false;
            out.append("{\"entry\":\"").append(Long.toHexString(entry.getOffset() - delta)).append('"');
            out.append(",\"size\":").append(Math.max(size, 0));
            out.append(",\"blocks\":").append(blocks);
            out.append(",\"thunk\":").append(f.isThunk());
            out.append(",\"name\":").append(esc(f.getName()));
            out.append(",\"calls\":[");
            boolean fc = true;
            for (Function c : f.getCalledFunctions(monitor)) {
                Address ce = c.getEntryPoint();
                if (c.isExternal() || !ce.isMemoryAddress()) continue;
                if (!fc) out.append(',');
                fc = false;
                out.append('"').append(Long.toHexString(ce.getOffset() - delta)).append('"');
            }
            out.append("]}");
        }
        out.append("]}");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            w.write(out.toString());
        }
    }
}
