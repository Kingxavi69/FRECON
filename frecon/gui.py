"""Tkinter desktop interface for FRECON."""

from __future__ import annotations

import json
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any

from frecon.scanner import check_web, create_report, parse_target, resolve_target, scan_ports


def format_report(report: dict[str, Any]) -> str:
    target = report["target"]
    lines = [
        "FRECON // RECONNAISSANCE REPORT",
        "=" * 72,
        f"Target:   {target['input']}",
        f"Resolved: {target['resolved_address']} ({target['address_family']})",
        f"Time:     {report['generated_at']}",
        "",
        "OPEN TCP PORTS",
        "-" * 72,
    ]
    ports = report["ports"]
    if ports:
        for port in ports:
            detail = " ".join(value for value in (port.get("product", ""), port.get("version", "")) if value)
            suffix = f"  {detail}" if detail else ""
            lines.append(f"{port['port']:<7}/tcp {port['service']}{suffix}")
    else:
        lines.append("None found in the selected port range.")

    findings = report["findings"]
    lines.extend(["", f"POTENTIAL SECURITY FINDINGS ({len(findings)})", "-" * 72])
    if findings:
        for finding in findings:
            lines.append(f"[{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"  Evidence: {finding['evidence']}")
            lines.append(f"  Action:   {finding['recommendation']}")
    else:
        lines.append("No indicators were identified by these checks.")

    web = report["web"]
    if web.get("http_error"):
        lines.extend(["", f"HTTP check: {web['http_error']}"])
    tls = web.get("tls")
    if isinstance(tls, dict) and tls.get("error"):
        lines.append(f"TLS check: {tls['error']}")
    lines.extend([
        "",
        "These are risk indicators, not confirmed vulnerabilities. Verify manually.",
    ])
    return "\n".join(lines)


class FreconWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FRECON | Recon Console")
        self.root.geometry("940x700")
        self.root.minsize(720, 540)
        self.root.configure(background="#101714")
        self.results: queue.Queue[tuple[str, object]] = queue.Queue()
        self.report: dict[str, Any] | None = None

        self.target = tk.StringVar()
        self.port_count = tk.StringVar(value="1000")
        self.authorized = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="READY  /  IDLE")
        self._configure_styles()
        self._build_layout()

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#101714")
        style.configure("Panel.TFrame", background="#18221d")
        style.configure("TLabel", background="#101714", foreground="#d9e4dc", font=("Consolas", 10))
        style.configure("Muted.TLabel", background="#101714", foreground="#8a9a8f", font=("Consolas", 9))
        style.configure("Title.TLabel", background="#101714", foreground="#c4f06a", font=("Consolas", 19, "bold"))
        style.configure("TEntry", fieldbackground="#0b100d", foreground="#e5f2e8", insertcolor="#c4f06a")
        style.configure("TSpinbox", fieldbackground="#0b100d", foreground="#e5f2e8", arrowsize=12)
        style.configure("TCheckbutton", background="#101714", foreground="#d9e4dc", font=("Consolas", 9))
        style.map("TCheckbutton", background=[("active", "#101714")], foreground=[("active", "#c4f06a")])
        style.configure("Run.TButton", background="#c4f06a", foreground="#101714", font=("Consolas", 10, "bold"), padding=(16, 9))
        style.map("Run.TButton", background=[("disabled", "#58634f"), ("active", "#d6ff8c")])
        style.configure("TButton", background="#26352c", foreground="#e5f2e8", font=("Consolas", 9), padding=(12, 8))
        style.map("TButton", background=[("active", "#35483a")])

    def _build_layout(self) -> None:
        container = ttk.Frame(self.root, padding=22)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(3, weight=1)

        header = ttk.Frame(container)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="FRECON", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="AUTHORIZED RECONNAISSANCE CONSOLE", style="Muted.TLabel").grid(
            row=0, column=1, sticky="e", padx=(16, 0)
        )

        controls = ttk.Frame(container, style="Panel.TFrame", padding=16)
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        controls.columnconfigure(0, weight=1)
        ttk.Label(controls, text="TARGET  /  IP, HOSTNAME, OR HTTP(S) URL").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        self.target_entry = ttk.Entry(controls, textvariable=self.target, font=("Consolas", 11))
        self.target_entry.grid(row=1, column=0, sticky="ew", padx=(0, 12))
        self.target_entry.bind("<Return>", lambda _event: self.start_scan())

        right = ttk.Frame(controls, style="Panel.TFrame")
        right.grid(row=0, column=1, rowspan=2, sticky="ns")
        ttk.Label(right, text="TOP TCP PORTS").pack(anchor="w", pady=(0, 6))
        self.ports_spinbox = ttk.Spinbox(right, from_=1, to=1000, increment=100, width=8, textvariable=self.port_count)
        self.ports_spinbox.pack(anchor="w")

        auth_row = ttk.Frame(container)
        auth_row.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        self.auth_check = ttk.Checkbutton(
            auth_row,
            text="I own this target or have permission to scan it",
            variable=self.authorized,
        )
        self.auth_check.pack(side="left", anchor="w")
        self.run_button = ttk.Button(auth_row, text="▶  RUN RECON", style="Run.TButton", command=self.start_scan)
        self.run_button.pack(side="right")
        self.save_button = ttk.Button(auth_row, text="SAVE JSON", command=self.save_report, state="disabled")
        self.save_button.pack(side="right", padx=(0, 8))

        output_frame = ttk.Frame(container)
        output_frame.grid(row=3, column=0, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        self.output = tk.Text(
            output_frame,
            wrap="word",
            state="disabled",
            background="#080c0a",
            foreground="#c4d5c9",
            insertbackground="#c4f06a",
            selectbackground="#405c46",
            borderwidth=0,
            padx=16,
            pady=14,
            font=("Consolas", 10),
            spacing1=2,
            spacing3=2,
        )
        self.output.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.output.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.tag_configure("heading", foreground="#c4f06a", font=("Consolas", 10, "bold"))
        self._write_output("FRECON READY\n\nEnter a single target, confirm scan permission, then run reconnaissance.\n\nNmap must be installed on this system. Results are indicators, not confirmed vulnerabilities.")

        footer = ttk.Frame(container)
        footer.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(footer, textvariable=self.status, style="Muted.TLabel").pack(side="left")
        ttk.Label(footer, text="TCP CONNECT  /  HTTP HEAD  /  TLS CERTIFICATE", style="Muted.TLabel").pack(side="right")

    def _write_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")
        self.output.see("1.0")

    def start_scan(self) -> None:
        if not self.authorized.get():
            messagebox.showwarning("Permission required", "Confirm that you own this target or have permission to scan it.", parent=self.root)
            return
        target_value = self.target.get().strip()
        if not target_value:
            messagebox.showwarning("Target required", "Enter an IP address, hostname, or HTTP(S) URL.", parent=self.root)
            self.target_entry.focus_set()
            return
        try:
            port_count = int(self.port_count.get())
            if not 1 <= port_count <= 1000:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Invalid port count", "Choose a number between 1 and 1000.", parent=self.root)
            return

        self.report = None
        self.save_button.configure(state="disabled")
        self.run_button.configure(state="disabled")
        self.status.set("SCANNING  /  PLEASE WAIT")
        self._write_output(f"Starting authorized reconnaissance for {target_value}...\n\nThe scan may take up to 110 seconds.")
        threading.Thread(target=self._scan, args=(target_value, port_count), daemon=True).start()
        self.root.after(150, self._poll_results)

    def _scan(self, target_value: str, port_count: int) -> None:
        try:
            target = resolve_target(parse_target(target_value))
            ports = scan_ports(target, port_count)
            web = check_web(target)
            report = create_report(target, ports, web)
        except (RuntimeError, ValueError, OSError) as error:
            self.results.put(("error", str(error)))
            return
        self.results.put(("success", report))

    def _poll_results(self) -> None:
        try:
            result_type, value = self.results.get_nowait()
        except queue.Empty:
            self.root.after(150, self._poll_results)
            return

        self.run_button.configure(state="normal")
        if result_type == "error":
            self.status.set("SCAN FAILED  /  CHECK ERROR BELOW")
            self._write_output(f"SCAN FAILED\n\n{value}")
            return

        self.report = value  # type: ignore[assignment]
        self.status.set("COMPLETE  /  REVIEW FINDINGS")
        self.save_button.configure(state="normal")
        self._write_output(format_report(self.report))

    def save_report(self) -> None:
        if self.report is None:
            return
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save FRECON JSON report",
            defaultextension=".json",
            initialfile="frecon-report.json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            with open(destination, "w", encoding="utf-8") as report_file:
                json.dump(self.report, report_file, indent=2)
                report_file.write("\n")
        except OSError as error:
            messagebox.showerror("Save failed", str(error), parent=self.root)
            return
        self.status.set(f"REPORT SAVED  /  {destination}")


def main() -> None:
    try:
        root = tk.Tk()
    except tk.TclError as error:
        print(f"FRECON GUI could not start: {error}\nOn Kali, install Tk with: sudo apt install python3-tk", file=sys.stderr)
        raise SystemExit(1) from error
    FreconWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()