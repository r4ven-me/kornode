import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { Ban, Eraser, LogOut, Terminal } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { createTerminalSession } from "./api";

type NoticeKind = "ok" | "warning" | "error";

export function TerminalView({
  authToken,
  theme,
  onNotice
}: {
  authToken: string;
  theme: "light" | "dark";
  onNotice: (kind: NoticeKind, text: string) => void;
}) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const [cwd, setCwd] = useState("/");
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);

  const disconnect = useCallback(() => {
    socketRef.current?.close();
    socketRef.current = null;
    setConnected(false);
    setConnecting(false);
  }, []);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) {
      return;
    }
    const terminal = new XTerm({
      cursorBlink: true,
      convertEol: false,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 14,
      scrollback: 5000,
      theme: terminalTheme(theme)
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(host);
    fitAddon.fit();
    terminal.write("Terminal is disconnected.\r\n");
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    const dataSubscription = terminal.onData((data) => {
      const socket = socketRef.current;
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "input", data }));
      }
    });
    const resizeSubscription = terminal.onResize(({ rows, cols }) => {
      const socket = socketRef.current;
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "resize", rows, cols }));
      }
    });
    const observer = new ResizeObserver(() => fitAddon.fit());
    observer.observe(host);

    return () => {
      observer.disconnect();
      dataSubscription.dispose();
      resizeSubscription.dispose();
      socketRef.current?.close();
      socketRef.current = null;
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.options.theme = terminalTheme(theme);
    }
  }, [theme]);

  const connect = async () => {
    const terminal = terminalRef.current;
    if (!terminal || socketRef.current?.readyState === WebSocket.OPEN) {
      return;
    }
    setConnecting(true);
    terminal.write("\r\n[connecting]\r\n");
    try {
      fitAddonRef.current?.fit();
      const session = await createTerminalSession(authToken, {
        cwd,
        rows: clamp(terminal.rows, 10, 80),
        cols: clamp(terminal.cols, 40, 240)
      });
      const socketUrl = new URL("/api/terminal/ws", window.location.href);
      socketUrl.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      socketUrl.searchParams.set("token", session.token);
      const socket = new WebSocket(socketUrl);
      socketRef.current = socket;
      socket.onopen = () => {
        setConnected(true);
        setConnecting(false);
        terminal.focus();
      };
      socket.onmessage = (event) => terminal.write(String(event.data));
      socket.onerror = () => {
        onNotice("error", "terminal connection error");
        terminal.write("\r\n[terminal connection error]\r\n");
      };
      socket.onclose = () => {
        if (socketRef.current === socket) {
          socketRef.current = null;
        }
        setConnected(false);
        setConnecting(false);
        terminal.write("\r\n[disconnected]\r\n");
      };
    } catch (error) {
      setConnecting(false);
      onNotice("error", error instanceof Error ? error.message : String(error));
    }
  };

  const interrupt = () => {
    const socket = socketRef.current;
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "input", data: "\u0003" }));
    }
    terminalRef.current?.focus();
  };

  return (
    <div className="view-stack">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Runtime shell</h2>
            <p className="muted-line">
              Root shell inside the running container; all sessions are audited
            </p>
          </div>
          <div className="toolbar">
            <span className={`pill ${connected ? "ok" : "muted"}`}>
              {connected ? "Connected" : connecting ? "Connecting" : "Closed"}
            </span>
            <button
              className="action-button"
              disabled={connected || connecting}
              onClick={() => void connect()}
              type="button"
            >
              <Terminal size={17} aria-hidden="true" />
              <span>Connect</span>
            </button>
            <button
              className="action-button"
              disabled={!connected}
              onClick={disconnect}
              type="button"
            >
              <LogOut size={17} aria-hidden="true" />
              <span>Disconnect</span>
            </button>
            <button
              className="action-button danger"
              disabled={!connected}
              onClick={interrupt}
              type="button"
            >
              <Ban size={17} aria-hidden="true" />
              <span>Ctrl-C</span>
            </button>
            <button
              className="action-button"
              onClick={() => terminalRef.current?.clear()}
              type="button"
            >
              <Eraser size={17} aria-hidden="true" />
              <span>Clear</span>
            </button>
          </div>
        </div>
        <label>
          <span>Working directory</span>
          <input
            disabled={connected || connecting}
            value={cwd}
            onChange={(event) => setCwd(event.target.value)}
            required
          />
        </label>
      </section>
      <section className="panel terminal-panel">
        <div className="xterm-host" ref={hostRef} />
      </section>
    </div>
  );
}

function terminalTheme(theme: "light" | "dark") {
  void theme;
  return {
    background: "#2e3440",
    foreground: "#d8dee9",
    cursor: "#88c0d0",
    selectionBackground: "#4c566a",
    black: "#3b4252",
    brightBlack: "#4c566a",
    red: "#bf616a",
    brightRed: "#bf616a",
    green: "#a3be8c",
    brightGreen: "#a3be8c",
    yellow: "#ebcb8b",
    brightYellow: "#ebcb8b",
    blue: "#81a1c1",
    brightBlue: "#81a1c1",
    magenta: "#b48ead",
    brightMagenta: "#b48ead",
    cyan: "#88c0d0",
    brightCyan: "#8fbcbb",
    white: "#e5e9f0",
    brightWhite: "#eceff4"
  };
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}
