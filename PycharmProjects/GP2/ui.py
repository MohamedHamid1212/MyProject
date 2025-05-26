import tkinter as tk
from tkinter import filedialog, messagebox, Text
from tkinter.ttk import Progressbar, Style, Scrollbar as TTKScrollbar
from scanner import scan_folder_local, scan_folder_virustotal
from utils import (
    generate_virus_by_type,
    quarantine_files,
    open_folder,
    log_quarantine,
    load_quarantine_info,
    move_quarantined_files
)
import threading
import time

selected_folder = ""
scanned_files = []
detected_files = []
quarantine_path = ""
quarantined_files = []

quarantine_path, quarantined_files = load_quarantine_info()

def apply_hacker_theme(window, widgets):
    bg_color = "#121212"
    fg_color = "#00FF00"
    button_bg = "#222222"
    button_fg = "#00FF00"
    font_mono = ("Consolas", 11)

    window.configure(bg=bg_color)
    for w in widgets:
        try:
            w.configure(bg=bg_color, fg=fg_color, font=font_mono)
            if isinstance(w, tk.Button):
                w.configure(bg=button_bg, fg=button_fg, activebackground=fg_color, activeforeground=bg_color, relief="flat")
            if isinstance(w, tk.Label):
                w.configure(font=("Consolas", 12, "bold"))
        except:
            pass

def choose_folder(label):
    global selected_folder
    folder = filedialog.askdirectory()
    if folder:
        selected_folder = folder
        label.config(text=f"Selected: {folder}")

def handle_generate_by_type(virus_type):
    generate_virus_by_type(virus_type)
    messagebox.showinfo("Done", f"Fake '{virus_type}' virus generated.")

def handle_scan_local(progress, result_text, quarantine_btn, spinner_label):
    global scanned_files, detected_files

    def scan():
        global scanned_files, detected_files
        scanning = [True]

        def animate_spinner():
            frames = ["|", "/", "-", "\\"]
            idx = 0
            while scanning[0]:
                spinner_label.config(text=f"Scanning locally... {frames[idx % 4]}")
                idx += 1
                time.sleep(0.1)

        threading.Thread(target=animate_spinner, daemon=True).start()

        result_text.config(state="normal")
        result_text.delete("1.0", tk.END)
        scanned_files, detected_files = scan_folder_local(selected_folder, progress)
        scanning[0] = False
        spinner_label.config(text="")
        progress.stop()

        if detected_files:
            result_text.insert(tk.END, "🚨 Suspicious files detected:\n" + "\n".join(detected_files))
            quarantine_btn.config(state=tk.NORMAL)
        else:
            result_text.insert(tk.END, "✅ No suspicious files found locally.")
            quarantine_btn.config(state=tk.DISABLED)
        result_text.config(state="disabled")

    progress.start(10)
    threading.Thread(target=scan).start()

def handle_scan_virustotal(result_text, progress, quarantine_btn, spinner_label):
    global scanned_files

    def scan():
        global scanned_files
        scanning = [True]

        def animate_spinner():
            frames = ["|", "/", "-", "\\"]
            idx = 0
            while scanning[0]:
                spinner_label.config(text=f"Scanning with VirusTotal... {frames[idx % 4]}")
                idx += 1
                time.sleep(0.1)

        threading.Thread(target=animate_spinner, daemon=True).start()

        result_text.config(state="normal")
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "🦠 Scanning files with VirusTotal...\n")
        result_text.config(state="disabled")

        scanned_files, results = scan_folder_virustotal(selected_folder, progress)
        scanning[0] = False
        spinner_label.config(text="")
        progress.stop()

        def update_result():
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, "\n".join(results))
            result_text.config(state="disabled")
            quarantine_btn.config(state=tk.NORMAL)

        result_text.after(0, update_result)

    progress.start(10)
    threading.Thread(target=scan).start()

def handle_quarantine(result_text, open_btn):
    global quarantine_path, quarantined_files, scanned_files
    if not scanned_files:
        messagebox.showerror("Error", "No files scanned to quarantine.")
        return

    folder = filedialog.askdirectory(title="Select Quarantine Folder")
    if folder:
        quarantine_path = folder
    else:
        messagebox.showerror("Error", "No quarantine path selected.")
        return

    quarantine_path = quarantine_files(selected_folder, scanned_files, quarantine_path)
    quarantined_files = scanned_files
    log_quarantine(quarantine_path, scanned_files)

    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"✅ Files moved to quarantine at: {quarantine_path}")
    result_text.config(state="disabled")

    open_btn.config(state=tk.NORMAL)

def handle_move_quarantined_files():
    global quarantine_path, quarantined_files
    if not quarantined_files:
        messagebox.showerror("Error", "No quarantined files to move.")
        return

    new_path = filedialog.askdirectory(title="Select New Quarantine Path")
    if new_path:
        move_quarantined_files(quarantine_path, new_path, quarantined_files)
        messagebox.showinfo("Success", f"Files moved to: {new_path}")
        quarantine_path = new_path
    else:
        messagebox.showerror("Error", "No path selected for moving files.")

def run_gui():
    window = tk.Tk()
    window.title("🛡️ Malware Detection & Generator")
    window.geometry("720x660")

    style = Style()
    style.theme_use("default")
    style.configure("TButton", font=('Consolas', 11), padding=6)
    style.configure("green.Horizontal.TProgressbar", troughcolor="#333333",
                    bordercolor="#333333", background="#00FF00", lightcolor="#00FF00", darkcolor="#00AA00")

    widgets = []

    title = tk.Label(window, text="🛡️ Malware Detection & Generator", bg="#121212", fg="#00FF00",
                     font=("Consolas", 20, "bold"))
    title.pack(pady=10)
    widgets.append(title)

    # Virus Generator Section
    generator_frame = tk.Frame(window, bg="#121212")
    tk.Label(generator_frame, text="🧬 Generate Virus Type:", font=("Consolas", 12, "bold"),
             bg="#121212", fg="#00FF00").grid(row=0, column=0, columnspan=3, pady=5)

    buttons = [
        ("🔊 Beeper", "beeper"),
        ("💥 Message Spam", "message_spam"),
        ("⚠️ EICAR Test", "eicar"),
    ]

    for idx, (label, vtype) in enumerate(buttons):
        btn = tk.Button(generator_frame, text=label, width=18, bg="#222", fg="#00FF00",
                        activebackground="#00FF00", activeforeground="#121212", relief="flat",
                        font=("Consolas", 10, "bold"),
                        command=lambda vt=vtype: handle_generate_by_type(vt))
        btn.grid(row=1 + idx // 3, column=idx % 3, padx=5, pady=3)
        widgets.append(btn)

    tk.Button(generator_frame, text="📂 Open Virus Folder", command=lambda: open_folder("simulated_virus"),
              bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212", relief="flat",
              font=("Consolas", 10, "bold"), width=56).grid(row=5, column=0, columnspan=3, pady=5)
    generator_frame.pack(pady=5)
    widgets.append(generator_frame)

    # Scan Section
    scan_frame = tk.Frame(window, bg="#121212")
    tk.Label(scan_frame, text="📁 Folder to Scan:", font=("Consolas", 12, "bold"), bg="#121212", fg="#00FF00").pack()
    folder_label = tk.Label(scan_frame, text="No folder selected.", bg="#121212", fg="#00FF00", font=("Consolas", 10))
    folder_label.pack(pady=2)
    widgets.append(folder_label)

    tk.Button(scan_frame, text="📂 Choose Folder", command=lambda: choose_folder(folder_label), width=25,
              bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212", relief="flat",
              font=("Consolas", 10, "bold")).pack(pady=5)

    progress = Progressbar(scan_frame, length=500, style="green.Horizontal.TProgressbar", mode="indeterminate")
    progress.pack(pady=5)

    spinner_label = tk.Label(scan_frame, text="", font=("Consolas", 10), bg="#121212", fg="#00FF00")
    spinner_label.pack()
    widgets.append(spinner_label)

    result_frame = tk.Frame(scan_frame, bg="#121212", bd=2, relief="sunken")
    result_frame.pack(pady=5)

    result_text = Text(result_frame, height=12, width=70, wrap="word",
                       bg="#1E1E1E", fg="#00FF00", insertbackground="#00FF00",
                       font=("Consolas", 10), bd=0, padx=10, pady=5)
    result_text.grid(row=0, column=0, sticky="nsew")

    scrollbar = TTKScrollbar(result_frame, orient="vertical", command=result_text.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    result_text.config(yscrollcommand=scrollbar.set)

    result_frame.grid_rowconfigure(0, weight=1)
    result_frame.grid_columnconfigure(0, weight=1)
    widgets.append(result_text)
    result_text.config(state="disabled")

    quarantine_btn = tk.Button(scan_frame, text="🔒 Quarantine Files", state=tk.DISABLED,
                               width=25, command=lambda: handle_quarantine(result_text, open_quarantine_btn),
                               bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212",
                               relief="flat", font=("Consolas", 10, "bold"))
    quarantine_btn.pack(pady=2)
    widgets.append(quarantine_btn)

    tk.Button(scan_frame, text="🔍 Scan Locally", command=lambda: handle_scan_local(progress, result_text, quarantine_btn, spinner_label),
              width=25,
              bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212", relief="flat",
              font=("Consolas", 10, "bold")).pack(pady=5)

    tk.Button(scan_frame, text="🦠 Scan using VirusTotal", command=lambda: handle_scan_virustotal(result_text, progress, quarantine_btn, spinner_label),
              width=25,
              bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212", relief="flat",
              font=("Consolas", 10, "bold")).pack(pady=5)

    scan_frame.pack(pady=10)
    widgets.append(scan_frame)

    # Quarantine Section
    quarantine_frame = tk.Frame(window, bg="#121212")

    open_quarantine_btn = tk.Button(quarantine_frame, text="📂 Open Quarantine",
                                    command=lambda: open_folder(quarantine_path), state=tk.DISABLED, width=25,
                                    bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212",
                                    relief="flat", font=("Consolas", 10, "bold"))
    open_quarantine_btn.pack(pady=2)
    widgets.append(open_quarantine_btn)

    move_quarantine_btn = tk.Button(quarantine_frame, text="🔄 Move Quarantined Files",
                                    command=handle_move_quarantined_files, width=25,
                                    bg="#222", fg="#00FF00", activebackground="#00FF00", activeforeground="#121212",
                                    relief="flat", font=("Consolas", 10, "bold"))
    move_quarantine_btn.pack(pady=5)
    widgets.append(move_quarantine_btn)

    quarantine_frame.pack(pady=10)
    widgets.append(quarantine_frame)

    apply_hacker_theme(window, widgets)
    window.mainloop()