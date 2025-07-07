import socket
import tkinter as tk
from tkinter import messagebox, END, filedialog, ttk
import threading
import time

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Alt"
}

root = tk.Tk()
root.title("Simple Port Scanner")
root.geometry("650x600")
root.configure(bg="#f0f0f0")


start_time = tk.DoubleVar()
dark_mode = False

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def start_scan():
    host = entry_host.get().strip()
    port_range = entry_ports.get().strip()

    if not host:
        messagebox.showerror("Input Error", "Please enter a valid host.")
        return

    try:
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        messagebox.showerror("Input Error", "Port range must be in format 'start-end'")
        return

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        messagebox.showerror("Input Error", "Port range must be between 1 and 65535")
        return

    output_text.delete(1.0, END)
    progress_bar['value'] = 0
    progress_bar['maximum'] = end_port - start_port + 1
    progress_label.config(text="0%")
    scan_button.config(state='disabled')
    export_button.config(state='disabled')
    start_time.set(time.time())

    thread = threading.Thread(target=scan_and_show_summary, args=(host, start_port, end_port))
    thread.start()

def scan_and_show_summary(host, start_port, end_port):
    open_ports = []
    total_ports = end_port - start_port + 1

    for i, port in enumerate(range(start_port, end_port + 1)):
        is_open = scan_port(host, port)
        service = COMMON_PORTS.get(port, "Unknown Service")
        status = "\u2705 Open" if is_open else "\u274C Closed"

        def update_output(p=port, s=status, idx=i):
            output_text.insert(END, f"Port {p}: {s}\n")
            output_text.see(END)
            progress_bar['value'] = idx + 1
            percent = int(((idx + 1) / total_ports) * 100)
            progress_label.config(text=f"{percent}%")

        root.after(0, update_output)

        if is_open:
            open_ports.append((port, service))

    def show_summary():
        duration = round(time.time() - start_time.get(), 2)
        output_text.insert(END, f"\n=== Summary of Open Ports (Scanned in {duration} sec) ===\n")
        if open_ports:
            for port, service in open_ports:
                output_text.insert(END, f"Port {port}: {service} (Open)\n")
        else:
            output_text.insert(END, "No open ports found.\n")
        output_text.see(END)
        scan_button.config(state='normal')
        export_button.config(state='normal')

    root.after(0, show_summary)

def export_results():
    result = output_text.get("1.0", END).strip()
    if not result:
        messagebox.showinfo("No Data", "Nothing to export.")
        return

    file = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text Files", "*.txt")],
                                         title="Save scan results")
    if file:
        with open(file, 'w') as f:
            f.write(result)
        messagebox.showinfo("Export Successful", f"Results saved to {file}")

def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode

    bg_color = "#2e2e2e" if dark_mode else "#f0f0f0"
    fg_color = "white" if dark_mode else "black"
    text_bg = "#1e1e1e" if dark_mode else "#ffffff"
    text_fg = "white" if dark_mode else "black"

    root.configure(bg=bg_color)
    for widget in root.winfo_children():
        if isinstance(widget, (tk.Label, tk.Entry, tk.Frame)):
            try:
                widget.configure(bg=bg_color, fg=fg_color)
            except:
                pass
    output_frame.configure(bg=bg_color)
    output_text.configure(bg=text_bg, fg=text_fg)
    progress_label.configure(bg=bg_color, fg=fg_color)

    toggle_btn.configure(bg="#444", fg="white" if dark_mode else "black")
    scan_button.configure(bg="#2196F3", fg="white")
    export_button.configure(bg="#4CAF50", fg="white")

toggle_btn = tk.Button(root, text="Toggle Theme", command=toggle_theme, bg="#555555", fg="white")
toggle_btn.pack(pady=5)

tk.Label(root, text="Target Host:", bg="#f0f0f0", font=("Segoe UI", 10)).pack(pady=5)
entry_host = tk.Entry(root, width=50)
entry_host.pack()

tk.Label(root, text="Port Range (e.g., 20-80):", bg="#f0f0f0", font=("Segoe UI", 10)).pack(pady=5)
entry_ports = tk.Entry(root, width=50)
entry_ports.pack()

scan_button = tk.Button(root, text="\u26A1 Scan Ports", command=start_scan, bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"))
scan_button.pack(pady=10)

progress_frame = tk.Frame(root, bg="#f0f0f0")
progress_frame.pack(pady=5)
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(side=tk.LEFT)
progress_label = tk.Label(progress_frame, text="0%", bg="#f0f0f0")
progress_label.pack(side=tk.LEFT, padx=10)

output_frame = tk.Frame(root, bg="#f0f0f0")
output_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(output_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output_text = tk.Text(output_frame, height=18, width=80, yscrollcommand=scrollbar.set, wrap='none', bg="#ffffff")
output_text.pack(fill=tk.BOTH, expand=True)
scrollbar.config(command=output_text.yview)

export_button = tk.Button(root, text="↓ Export Results", command=export_results, state='disabled', bg="#4CAF50", fg="white", font=("Segoe UI", 9, "bold"))
export_button.configure(fg="white")
export_button.pack(pady=10)

root.mainloop()
