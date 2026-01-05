import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebglAddon } from "@xterm/addon-webgl";
import "@xterm/xterm/css/xterm.css";

interface Props {
  onData: (data: string) => void;
  onResize: (cols: number, rows: number) => void;
  onOutput?: (cb: (data: string) => void) => void;
  onClosed?: (cb: (status: number | null) => void) => void;
}

export function TermView({ onData, onResize, onOutput, onClosed }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);

  useEffect(() => {
    if (!container.current) return;
    const t = new Terminal({
      cursorBlink: true,
      fontFamily: "Consolas, 'Cascadia Mono', monospace",
      fontSize: 13,
      theme: {
        background: "#0d1117",
        foreground: "#e6edf3",
        cursor: "#e6edf3",
        selectionBackground: "#3b4261",
      },
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    const search = new SearchAddon();
    t.loadAddon(fit);
    t.loadAddon(search);
    try {
      t.loadAddon(new WebglAddon());
    } catch {
      // WebGL unavailable — fall back to the canvas/dom renderer.
    }
    t.open(container.current);
    term.current = t;
    fit.fit();

    t.onData((d) => onData(d));
    t.onResize(({ cols, rows }) => onResize(cols, rows));

    const ro = new ResizeObserver(() => {
      try { fit.fit(); } catch { /* not attached yet */ }
    });
    ro.observe(container.current);

    onOutput?.((data) => t.write(data));
    onClosed?.((status) => {
      t.write(`\r\n\x1b[2m[session closed${status != null ? ` (exit ${status})` : ""}]\x1b[0m\r\n`);
    });

    return () => {
      ro.disconnect();
      t.dispose();
      term.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <div ref={container} className="term-container" />;
}
