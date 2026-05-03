import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk


class AutoResponseUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Auto Response")
        self.root.geometry("1280x720")
        self.root.minsize(1000, 600)

        self.page_bg = "#30351D"
        self.panel_bg = "#000000"
        self.panel_text = "#FFFFFF"

        self.project_root = Path(__file__).resolve().parent
        self.reports_dir = self.project_root / "reports"

        self.process = None
        self.output_queue: queue.Queue[tuple[str, str]] = queue.Queue()

        self._configure_layout()
        self._build_widgets()

        self.root.after(100, self._drain_output_queue)
        self.root.after(1000, self._refresh_report_views)

    def _configure_layout(self) -> None:
        self.root.configure(bg=self.page_bg)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "LowProfile.Vertical.TScrollbar",
            background="#1c1c1c",
            troughcolor=self.panel_bg,
            bordercolor=self.panel_bg,
            arrowcolor="#7a7a7a",
            lightcolor=self.panel_bg,
            darkcolor=self.panel_bg,
            gripcount=0,
            relief="flat",
            width=8,
        )
        style.map(
            "LowProfile.Vertical.TScrollbar",
            background=[("active", "#2a2a2a"), ("pressed", "#3a3a3a")],
            arrowcolor=[("active", "#bcbcbc")],
        )
        self.root.grid_columnconfigure(0, weight=1, uniform="main")
        self.root.grid_columnconfigure(1, weight=1, uniform="main")
        self.root.grid_rowconfigure(0, weight=1)

    def _build_widgets(self) -> None:
        left_panel = tk.Frame(self.root, bg=self.page_bg)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(14, 7), pady=14)
        left_panel.grid_rowconfigure(0, weight=1)
        left_panel.grid_rowconfigure(1, weight=1)
        left_panel.grid_columnconfigure(0, weight=1)

        top_left = tk.Frame(left_panel, bg=self.page_bg)
        top_left.grid(row=0, column=0, sticky="nsew", pady=(0, 7))
        top_left.grid_rowconfigure(0, weight=1)
        top_left.grid_columnconfigure(0, weight=1)

        button_box = tk.Frame(
            top_left,
            bg=self.panel_bg,
            highlightthickness=2,
            highlightbackground="#222222",
            bd=0,
        )
        button_box.grid(row=0, column=0, sticky="nw", padx=6, pady=6)

        self.run_button = tk.Button(
            button_box,
            text="Run",
            command=self._start_pipeline,
            bg=self.panel_bg,
            activebackground="#1a1a1a",
            fg=self.panel_text,
            activeforeground=self.panel_text,
            font=("Segoe UI", 12, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2",
        )
        self.run_button.pack()

        self.title_label = tk.Label(
            top_left,
            text="Auto Response",
            bg=self.page_bg,
            fg=self.panel_text,
            font=("Segoe UI", 22, "bold"),
            anchor="center",
        )
        self.title_label.grid(row=0, column=0, sticky="n", pady=(95, 0))

        self.status_label = tk.Label(
            top_left,
            text="Status: idle",
            bg=self.page_bg,
            fg=self.panel_text,
            font=("Segoe UI", 11),
            anchor="w",
        )
        self.status_label.grid(row=0, column=0, sticky="sw", padx=12, pady=10)

        terminal_frame = tk.Frame(
            left_panel,
            bg=self.panel_bg,
            highlightthickness=2,
            highlightbackground="#111111",
        )
        terminal_frame.grid(row=1, column=0, sticky="nsew", pady=(7, 0))
        terminal_frame.grid_rowconfigure(0, weight=1)
        terminal_frame.grid_columnconfigure(0, weight=1)

        self.terminal_output = tk.Text(
            terminal_frame,
            wrap="word",
            bg=self.panel_bg,
            fg=self.panel_text,
            insertbackground=self.panel_text,
            relief="flat",
            font=("Consolas", 11),
            padx=8,
            pady=8,
        )
        terminal_scroll = ttk.Scrollbar(
            terminal_frame,
            orient="vertical",
            command=self.terminal_output.yview,
            style="LowProfile.Vertical.TScrollbar",
        )
        self.terminal_output.configure(yscrollcommand=terminal_scroll.set)

        self.terminal_output.grid(row=0, column=0, sticky="nsew")
        terminal_scroll.grid(row=0, column=1, sticky="ns")

        right_panel = tk.Frame(self.root, bg=self.page_bg)
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 14), pady=14)
        right_panel.grid_rowconfigure(0, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_columnconfigure(1, weight=1)

        report_frame = tk.Frame(
            right_panel,
            bg=self.panel_bg,
            highlightthickness=2,
            highlightbackground="#111111",
        )
        report_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        report_frame.grid_rowconfigure(1, weight=1)
        report_frame.grid_columnconfigure(0, weight=1)

        report_title = tk.Label(
            report_frame,
            text="Most Recent Incident Report",
            bg=self.panel_bg,
            fg=self.panel_text,
            font=("Segoe UI", 12, "bold"),
            anchor="w",
            padx=8,
            pady=8,
        )
        report_title.grid(row=0, column=0, sticky="ew")

        self.report_text = tk.Text(
            report_frame,
            wrap="word",
            bg=self.panel_bg,
            fg=self.panel_text,
            insertbackground=self.panel_text,
            relief="flat",
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )
        self.report_text.tag_configure("headline", font=("Consolas", 11, "bold"))
        self.report_text.tag_configure("section", font=("Consolas", 10, "bold"))
        report_scroll = ttk.Scrollbar(
            report_frame,
            orient="vertical",
            command=self.report_text.yview,
            style="LowProfile.Vertical.TScrollbar",
        )
        self.report_text.configure(yscrollcommand=report_scroll.set)

        self.report_text.grid(row=1, column=0, sticky="nsew")
        report_scroll.grid(row=1, column=1, sticky="ns")

        ips_frame = tk.Frame(
            right_panel,
            bg=self.panel_bg,
            highlightthickness=2,
            highlightbackground="#111111",
        )
        ips_frame.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        ips_frame.grid_rowconfigure(1, weight=1)
        ips_frame.grid_columnconfigure(0, weight=1)

        ips_title = tk.Label(
            ips_frame,
            text="Containment State",
            bg=self.panel_bg,
            fg=self.panel_text,
            font=("Segoe UI", 12, "bold"),
            anchor="w",
            padx=8,
            pady=8,
        )
        ips_title.grid(row=0, column=0, sticky="ew")

        self.ip_list = tk.Listbox(
            ips_frame,
            bg=self.panel_bg,
            fg=self.panel_text,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            font=("Consolas", 11),
            activestyle="none",
            selectbackground="#2b2b2b",
            selectforeground=self.panel_text,
        )
        ips_scroll = ttk.Scrollbar(
            ips_frame,
            orient="vertical",
            command=self.ip_list.yview,
            style="LowProfile.Vertical.TScrollbar",
        )
        self.ip_list.configure(yscrollcommand=ips_scroll.set)

        self.ip_list.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        ips_scroll.grid(row=1, column=1, sticky="ns", pady=(0, 8))

    def _start_pipeline(self) -> None:
        if self.process and self.process.poll() is None:
            self._append_terminal("[UI] Pipeline is already running.\n")
            return

        self._append_terminal("\n[UI] Starting main.py...\n")
        self.status_label.config(text="Status: running")
        self.run_button.config(state="disabled")

        threading.Thread(target=self._run_main_in_subprocess, daemon=True).start()

    def _run_main_in_subprocess(self) -> None:
        command = [sys.executable, "-u", "main.py"]
        try:
            self.process = subprocess.Popen(
                command,
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            self.output_queue.put(("line", f"[UI] Failed to start main.py: {exc}\n"))
            self.output_queue.put(("done", "failed"))
            return

        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.output_queue.put(("line", line))

        exit_code = self.process.wait()
        status = "success" if exit_code == 0 else f"failed (exit code {exit_code})"
        self.output_queue.put(("line", f"\n[UI] main.py finished: {status}\n"))
        self.output_queue.put(("done", status))

    def _drain_output_queue(self) -> None:
        try:
            while True:
                item_type, payload = self.output_queue.get_nowait()
                if item_type == "line":
                    self._append_terminal(payload)
                elif item_type == "done":
                    self.status_label.config(text=f"Status: {payload}")
                    self.run_button.config(state="normal")
                    self._refresh_report_views()
        except queue.Empty:
            pass

        self.root.after(100, self._drain_output_queue)

    def _append_terminal(self, text: str) -> None:
        self.terminal_output.insert("end", text)
        self.terminal_output.see("end")

    def _latest_report_file(self) -> Path | None:
        if not self.reports_dir.exists():
            return None

        report_files = sorted(
            self.reports_dir.glob("incident_*.txt"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return report_files[0] if report_files else None

    def _refresh_report_views(self) -> None:
        latest_report = self._latest_report_file()
        if latest_report is None:
            self._set_report_text("No incident reports found yet. Run the pipeline to generate one.\n")
            self._set_firewall_state_entries([])
            self.root.after(2000, self._refresh_report_views)
            return

        try:
            latest_content = latest_report.read_text(encoding="utf-8")
        except OSError as exc:
            self._set_report_text(f"Failed to read latest report: {exc}\n")
            self._set_firewall_state_entries([])
            self.root.after(2000, self._refresh_report_views)
            return

        self._set_report_text(latest_content)

        entries = self._collect_firewall_state_entries()
        self._set_firewall_state_entries(entries)
        self.root.after(2000, self._refresh_report_views)

    def _set_report_text(self, text: str) -> None:
        self.report_text.config(state="normal")
        self.report_text.delete("1.0", "end")

        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if stripped.startswith("Incident Report -") or stripped.startswith("Generated:") or stripped.startswith("Status:"):
                self.report_text.insert("end", line, ("headline",))
            elif stripped.startswith("===================="):
                self.report_text.insert("end", line, ("section",))
            else:
                self.report_text.insert("end", line)

        self.report_text.config(state="disabled")

    def _collect_firewall_state_entries(self) -> list[str]:
        firewall_state_file = self.project_root / "agents" / "data" / "firewall_state.py"
        if not firewall_state_file.exists():
            return ["Firewall state file not found."]

        try:
            # Execute the file in a controlled namespace to extract FIREWALL_STATE
            namespace = {}
            with open(firewall_state_file, 'r', encoding='utf-8') as f:
                exec(f.read(), namespace)
            
            firewall_state = namespace.get('FIREWALL_STATE')
            if firewall_state is None:
                return ["Could not parse firewall state."]

            entries = []
            # Display each section with IPs
            sections = [
                ("Blocked IPs", firewall_state.get("blocked_ips", [])),
                ("Blocked Ports", firewall_state.get("blocked_ports", [])),
                ("Rate Limited IPs", firewall_state.get("rate_limited_ips", [])),
                ("Isolated Hosts", firewall_state.get("isolated_hosts", [])),
                ("Stopped Services", firewall_state.get("stopped_services", [])),
                ("Paused Processes", firewall_state.get("paused_processes", [])),
                ("Quarantined Hosts", firewall_state.get("quarantined_hosts", [])),
            ]
            
            network_stopped_count = firewall_state.get("network_stopped_count", 0)
            if network_stopped_count > 0:
                sections.append(("Network Stopped", [f"Count: {network_stopped_count}"]))
            
            snapshots = firewall_state.get("snapshots", [])
            if snapshots:
                sections.append(("Snapshots", [f"{s['target']} ({s['timestamp']})" for s in snapshots]))

            for section_name, items in sections:
                if items:
                    entries.append(f"{section_name}:")
                    for item in items[-5:]:  # Show only the most recent 5 items
                        entries.append(f"  {item}")
                    entries.append("")  # Empty line between sections

            return entries if entries else ["No containment data."]

        except Exception as exc:
            return [f"Error reading containment state: {exc}"]

        return entries

    def _set_firewall_state_entries(self, entries: list[str]) -> None:
        self.ip_list.delete(0, "end")
        if not entries:
            self.ip_list.insert("end", "No containment data.")
            return

        for entry in entries:
            self.ip_list.insert("end", entry)


def main() -> None:
    root = tk.Tk()
    app = AutoResponseUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
