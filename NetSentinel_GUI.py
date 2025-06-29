import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import webbrowser

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0
        widget.bind("<Enter>", self.enter)
        widget.bind("<Leave>", self.leave)
        widget.bind("<ButtonPress>", self.leave)

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(500, self.showtip)

    def unschedule(self):
        id_ = self.id
        self.id = None
        if id_:
            self.widget.after_cancel(id_)

    def showtip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert") if self.widget.winfo_ismapped() else (0, 0, 0, 0)
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=4, ipady=2)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class NetSentinelGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetSentinel GUI")
        self.geometry("800x600")
        self.create_menu()
        self.create_widgets()
        self.process = None
        self.scan_thread = None
        self.scan_running = False

    def create_menu(self):
        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Instructions", command=self.show_instructions)

        donate_menu = tk.Menu(help_menu, tearoff=0)
        donate_menu.add_command(label="GitHub: @kaotickj", command=lambda: self.open_donation_link("https://github.com/sponsors/kaotickj"))
        donate_menu.add_command(label="Patreon: KaotickJay", command=lambda: self.open_donation_link("https://patreon.com/KaotickJay"))
        donate_menu.add_command(label="PayPal: Donate Here", command=lambda: self.open_donation_link("https://paypal.me/kaotickj"))

        help_menu.add_cascade(label="Donate", menu=donate_menu)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def show_about(self):
        about_window = tk.Toplevel(self)
        about_window.title("About NetSentinel")
        about_window.geometry("400x200")
        about_window.resizable(False, False)
        tk.Label(about_window, text="NetSentinel", font=("Helvetica", 14, "bold")).pack(pady=10)
        tk.Label(about_window, text="A Network Reconnaissance Toolkit\nDeveloped by KaotickJ").pack(pady=5)

        def open_link(event):
            webbrowser.open_new("https://github.com/kaotickj/NetSentinel")

        link = tk.Label(about_window, text="https://github.com/kaotickj/NetSentinel", fg="blue", cursor="hand2")
        link.pack(pady=10)
        link.bind("<Button-1>", open_link)
        tk.Button(about_window, text="Close", command=about_window.destroy).pack(pady=10)

    def show_instructions(self):
        instructions_win = tk.Toplevel(self)
        instructions_win.title("NetSentinel Usage Instructions")
        instructions_win.geometry("500x300")
        instructions_win.resizable(False, False)

        tk.Label(instructions_win, text="Basic Usage", font=("Helvetica", 12, "bold")).pack(pady=10)
        tk.Label(instructions_win, text=(
            "1. Enter a target IP or CIDR range.\n"
            "2. Select the desired scan options.\n"
            "3. Optionally provide user/password lists.\n"
            "4. Click 'Run Scan' to begin enumeration.\n\n"
            "Tip: Enable 'HTML Report' to generate a web-based output summary."
        ), justify="left", anchor="w").pack(padx=20)

        def open_wiki(event=None):
            webbrowser.open_new("https://github.com/kaotickj/NetSentinel/wiki/Usage-Guide")

        link = tk.Label(instructions_win, text="📘 Open Full Usage Guide (Wiki)", fg="blue", cursor="hand2", font=("Helvetica", 10, "underline"))
        link.pack(pady=15)
        link.bind("<Button-1>", open_wiki)

        tk.Button(instructions_win, text="Close", command=instructions_win.destroy).pack(pady=5)

    def open_donation_link(self, url):
        webbrowser.open_new(url)

    def create_widgets(self):
        frm = ttk.Frame(self)
        frm.pack(padx=10, pady=10, fill="both", expand=True)

        opt_frame = ttk.LabelFrame(frm, text="Scan Options")
        opt_frame.pack(fill="x", pady=5)

        ttk.Label(opt_frame, text="Target IP or CIDR:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.target_entry = ttk.Entry(opt_frame, width=40)
        self.target_entry.grid(row=0, column=1, sticky="w", pady=2)
        ToolTip(self.target_entry, "Enter target IP address or CIDR range, e.g., 192.168.1.1 or 10.0.0.0/24")

        ttk.Label(opt_frame, text="Scan Type:").grid(row=0, column=2, sticky="e", padx=5)
        self.scan_type = tk.StringVar(value="quick")
        scan_type_combo = ttk.Combobox(opt_frame, textvariable=self.scan_type, values=["quick", "full"], width=10)
        scan_type_combo.grid(row=0, column=3)
        ToolTip(scan_type_combo, "Select scan type: quick or full")

        self.chk_resolve = tk.BooleanVar()
        chk_resolve_btn = ttk.Checkbutton(opt_frame, text="Resolve Hostnames", variable=self.chk_resolve)
        chk_resolve_btn.grid(row=1, column=0, sticky="w", padx=5)
        ToolTip(chk_resolve_btn, "Perform reverse DNS lookup to resolve hostnames")

        self.chk_smb = tk.BooleanVar()
        chk_smb_btn = ttk.Checkbutton(opt_frame, text="SMB Enumeration", variable=self.chk_smb)
        chk_smb_btn.grid(row=1, column=1, sticky="w")
        ToolTip(chk_smb_btn, "Enumerate SMB shares on target hosts")

        self.chk_kerberos = tk.BooleanVar()
        chk_kerberos_btn = ttk.Checkbutton(opt_frame, text="Kerberos Scan", variable=self.chk_kerberos)
        chk_kerberos_btn.grid(row=1, column=2, sticky="w")
        ToolTip(chk_kerberos_btn, "Perform Kerberos enumeration")

        self.chk_pspray = tk.BooleanVar()
        chk_pspray_btn = ttk.Checkbutton(opt_frame, text="Password Spray", variable=self.chk_pspray)
        chk_pspray_btn.grid(row=1, column=3, sticky="w")
        ToolTip(chk_pspray_btn, "Perform SMB password spraying attack")

        file_frame = ttk.LabelFrame(frm, text="Optional Inputs")
        file_frame.pack(fill="x", pady=5)

        self.user_file = tk.StringVar()
        ttk.Label(file_frame, text="User List:").grid(row=0, column=0, sticky="w", padx=5)
        user_entry = ttk.Entry(file_frame, textvariable=self.user_file, width=40)
        user_entry.grid(row=0, column=1)
        ToolTip(user_entry, "Path to file containing usernames for password spraying")
        ttk.Button(file_frame, text="Browse", command=lambda: self.select_file(self.user_file)).grid(row=0, column=2)

        self.pass_file = tk.StringVar()
        ttk.Label(file_frame, text="Password List:").grid(row=1, column=0, sticky="w", padx=5)
        pass_entry = ttk.Entry(file_frame, textvariable=self.pass_file, width=40)
        pass_entry.grid(row=1, column=1)
        ToolTip(pass_entry, "Path to file containing passwords for password spraying")
        ttk.Button(file_frame, text="Browse", command=lambda: self.select_file(self.pass_file)).grid(row=1, column=2)

        self.html_output = tk.StringVar()
        ttk.Label(file_frame, text="HTML Report:").grid(row=2, column=0, sticky="w", padx=5)
        html_entry = ttk.Entry(file_frame, textvariable=self.html_output, width=40)
        html_entry.grid(row=2, column=1)
        ToolTip(html_entry, "File path to save the HTML scan report")
        ttk.Button(file_frame, text="Save As", command=lambda: self.select_file(self.html_output, save=True)).grid(row=2, column=2)

        self.run_btn = ttk.Button(frm, text="Run Scan", command=self.run_scan_threaded)
        self.run_btn.pack(pady=10)
        ToolTip(self.run_btn, "Start the network scan with selected options")

        self.output_area = scrolledtext.ScrolledText(frm, wrap=tk.WORD, height=20, bg="#1e1e1e", fg="#00ff88")
        self.output_area.pack(fill="both", expand=True)
        ToolTip(self.output_area, "Output console showing scan progress and results")

    def select_file(self, var, save=False):
        path = filedialog.asksaveasfilename() if save else filedialog.askopenfilename()
        if path:
            var.set(path)

    def run_scan_threaded(self):
        if self.scan_running:
            self.stop_scan()
        else:
            self.scan_thread = threading.Thread(target=self.run_scan)
            self.scan_thread.start()
            self.run_btn.config(text="Stop Scan")
            self.scan_running = True

    def run_scan(self):
        self.output_area.delete(1.0, tk.END)
        cmd = ["python", "main.py", "--target", self.target_entry.get()]

        if self.scan_type.get():
            cmd += ["--scan-type", self.scan_type.get()]

        if self.chk_resolve.get():
            cmd.append("--resolve-hostnames")

        if self.chk_smb.get():
            cmd.append("--smb-enum")

        if self.chk_kerberos.get():
            cmd.append("--kerberos-scan")

        if self.chk_pspray.get():
            cmd.append("--password-spray")

        if self.user_file.get():
            cmd += ["--user-list", self.user_file.get()]

        if self.pass_file.get():
            cmd += ["--password-list", self.pass_file.get()]

        if self.html_output.get():
            cmd += ["--html-report", self.html_output.get()]

        self.output_area.insert(tk.END, f"Running:\n{' '.join(cmd)}\n\n")
        self.output_area.see(tk.END)

        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in self.process.stdout:
                if not self.scan_running:
                    self.process.terminate()
                    break
                self.output_area.insert(tk.END, line)
                self.output_area.see(tk.END)
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERROR] Failed to run scan: {e}")

        self.process = None
        self.run_btn.config(text="Run Scan")
        self.scan_running = False

    def stop_scan(self):
        self.scan_running = False
        if self.process:
            self.process.terminate()
        self.output_area.insert(tk.END, "\n[INFO] Scan stopped by user.\n")
        self.output_area.see(tk.END)
        self.run_btn.config(text="Run Scan")

if __name__ == "__main__":
    app = NetSentinelGUI()
    app.mainloop()

