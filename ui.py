import tkinter as tk
from tkinter import filedialog, messagebox, Text, Toplevel
from tkinter.ttk import Progressbar, Style
from scanner import scan_folder_local, scan_folder_virustotal
from utils import (
    generate_virus_by_type,
    quarantine_files,
    open_folder,
    log_quarantine,
    load_quarantine_info,
    move_quarantined_files,
    get_all_virus_paths_with_time,
    update_moved_virus_paths,
)
import threading
import time
import os

selected_folder = ""
scanned_files = []
detected_files = {}
quarantine_path, quarantined_files = load_quarantine_info()
theme_mode = "dark"
simulate_behavior = False  # Global toggle for virus simulation mode

THEMES = {
    "dark": {
        "bg": "#121212", "fg": "#00FF00",
        "button_bg": "#222222", "button_fg": "#00FF00",
        "entry_bg": "#1E1E1E", "frame_bg": "#121212",
        "label_frame_fg": "#00FF00", "menu_bg": "#1E1E1E",
        "menu_fg": "#00FF00", "font_title": ("Consolas", 22, "bold"),
        "font_label": ("Consolas", 12, "bold"), "font_button": ("Consolas", 10, "bold"),
        "font_menu": ("Consolas", 10)
    },
    "light": {
        "bg": "#FFFFFF", "fg": "#1F2937",
        "button_bg": "#E5E7EB", "button_fg": "#2563EB",
        "entry_bg": "#F9FAFB", "frame_bg": "#FFFFFF",
        "label_frame_fg": "#1F2937", "menu_bg": "#FFFFFF",
        "menu_fg": "#1F2937", "font_title": ("Consolas", 22, "bold"),
        "font_label": ("Consolas", 12, "bold"), "font_button": ("Consolas", 10, "bold"),
        "font_menu": ("Consolas", 10)
    }
}

def choose_folder(label):
    global selected_folder
    folder = filedialog.askdirectory()
    if folder:
        selected_folder = folder
        label.config(text=f"Selected: {folder}")
    else:
        label.config(text="No folder selected.")

def apply_theme(window, widgets, text_area, mode, menu=None):
    t = THEMES[mode]
    window.configure(bg=t["bg"])
    for w in widgets:
        try:
            if isinstance(w, (tk.Frame, tk.LabelFrame)):
                w.configure(bg=t["frame_bg"], highlightthickness=0, bd=0)
                if isinstance(w, tk.LabelFrame):
                    w.configure(fg=t["label_frame_fg"])
            elif isinstance(w, tk.Label):
                w.configure(bg=t["bg"], fg=t["fg"], font=t["font_label"])
            elif isinstance(w, tk.Button):
                w.configure(bg=t["button_bg"], fg=t["button_fg"], font=t["font_button"],
                            activebackground=t["button_fg"], activeforeground=t["bg"], relief="flat")
        except:
            pass
    text_area.configure(bg=t["entry_bg"], fg=t["fg"], insertbackground=t["fg"], font=("Consolas", 10))
    if menu:
        menu.configure(bg=t["menu_bg"], fg=t["menu_fg"], activebackground=t["menu_fg"],
                       activeforeground=t["menu_bg"], font=t["font_menu"])

def toggle_theme(window, widgets, text_area, menu):
    global theme_mode
    theme_mode = "light" if theme_mode == "dark" else "dark"
    apply_theme(window, widgets, text_area, theme_mode, menu)
def preview_behavior(vtype):
    descriptions = {
        "beeper": "Type: Beeper\n- Prints 'Beep!' in a loop 5 times with 1 second delay.\n- No files or system modified.",
        "message_spam": "Type: Message Spam\n- Launches 10 popup message boxes with the text: 'YOU HAVE BEEN HACKED'.",
        "wallpaper_changer": "Type: Wallpaper Changer\n- Calls Windows API to change desktop wallpaper to hacked.jpg from Desktop.",
        "eicar": "Type: EICAR Test\n- Generates the EICAR antivirus test string.\n- Used for testing antivirus detection (no real harm).",
        "folder_bomb": "Type: Folder Bomb\n- Creates 25 nested folders on your Desktop.\n- Annoying, but harmless."
    }

    popup = Toplevel()
    popup.title("🧬 Virus Behavior Preview")
    popup.geometry("500x300")
    popup.configure(bg=THEMES[theme_mode]["bg"])
    text = Text(popup, wrap="word", bg=THEMES[theme_mode]["entry_bg"],
                fg=THEMES[theme_mode]["fg"], font=("Consolas", 10))
    text.pack(expand=True, fill="both", padx=10, pady=10)
    text.insert("1.0", descriptions.get(vtype, "No preview available."))
    text.config(state="disabled")

def show_virus_paths_popup():
    popup = Toplevel()
    popup.title("🗂️ Virus Paths")
    popup.geometry("700x420")
    popup.configure(bg=THEMES[theme_mode]["bg"])

    def refresh():
        update_moved_virus_paths()
        virus_data = get_all_virus_paths_with_time()
        text.config(state="normal")
        text.delete("1.0", tk.END)
        if not virus_data:
            text.insert("1.0", "No virus paths found.")
        else:
            for name, data in virus_data.items():
                text.insert("end", f"{name} ➜ {data['path']}\nCreated: {data['created']}\n\n")
        text.config(state="disabled")

    refresh_btn = tk.Button(popup, text="🔄 Refresh", command=refresh,
                            bg=THEMES[theme_mode]["button_bg"],
                            fg=THEMES[theme_mode]["button_fg"],
                            relief="flat", font=THEMES[theme_mode]["font_button"])
    refresh_btn.pack(pady=5)

    text = Text(popup, wrap="word", bg=THEMES[theme_mode]["entry_bg"],
                fg=THEMES[theme_mode]["fg"], font=("Consolas", 10))
    text.pack(expand=True, fill="both", padx=10, pady=10)
    refresh()

def run_gui():
    global theme_mode, quarantine_path, quarantined_files, simulate_behavior
    window = tk.Tk()
    window.title("🛡️ Malware Tool")
    window.geometry("900x740")
    window.minsize(860, 720)
    window.resizable(True, True)

    style = Style()
    style.theme_use("default")
    style.configure("green.Horizontal.TProgressbar", troughcolor="#333", bordercolor="#333",
                    background="#00FF00", lightcolor="#00FF00", darkcolor="#00AA00")

    widgets = []

    header = tk.Frame(window)
    header.pack(fill="x", pady=5)
    title_label = tk.Label(header, text="🛡️ Malware Detection & Generator")
    title_label.pack(side="left", padx=20)
    widgets.extend([header, title_label])
    menu = tk.Menu(window, tearoff=0)
    settings_btn = tk.Button(header, text="⚙️ Settings", width=12)
    settings_btn.pack(side="right", padx=10)
    widgets.append(settings_btn)

    def toggle_simulation_mode():
        global simulate_behavior
        simulate_behavior = not simulate_behavior
        status = "ON" if simulate_behavior else "OFF"
        messagebox.showinfo("Simulation Mode", f"Virus behavior simulation is now {status}.")

    def show_settings(event=None):
        x, y = settings_btn.winfo_rootx(), settings_btn.winfo_rooty() + settings_btn.winfo_height()
        menu.tk_popup(x, y)

    def move_and_update_quarantine():
        global quarantine_path
        new_path = filedialog.askdirectory(title="Select New Quarantine Folder")
        if not new_path:
            return
        move_quarantined_files(quarantine_path, new_path, quarantined_files)
        quarantine_path = new_path
        with open("quarantine_info.txt", "w") as f:
            f.write(f"{quarantine_path}\n")
            for item in quarantined_files:
                f.write(f"{item}\n")
        messagebox.showinfo("Moved", f"Quarantined files moved to:\n{new_path}")

    settings_btn.bind("<Button-1>", show_settings)
    menu.add_command(label="🗂️ Viruses Paths", command=show_virus_paths_popup)
    menu.add_command(label="📂 Open Quarantine", command=lambda: open_folder(quarantine_path))
    menu.add_command(label="🔄 Move Quarantined Files", command=move_and_update_quarantine)
    menu.add_command(label="🌓 Toggle Light/Dark Mode", command=lambda: toggle_theme(window, widgets, result_text, menu))
    menu.add_command(label="🧪 Toggle Behavior Simulation", command=toggle_simulation_mode)

    generator = tk.LabelFrame(window, text="🧬 Virus Generator", padx=10, pady=10)
    generator.pack(pady=10, padx=20, fill="x")
    widgets.append(generator)

    for text, vtype in [
        ("🔊 Beeper", "beeper"),
        ("💥 Message Spam", "message_spam"),
        ("⚠️ EICAR Test", "eicar"),
        ("🖼️ Wallpaper", "wallpaper_changer"),
        ("🗂️ Folder Bomb", "folder_bomb")
    ]:
        def handle_generation(vt=vtype):
            if simulate_behavior:
                preview_behavior(vt)
            else:
                generate_virus_by_type(vt)
                update_moved_virus_paths()
                messagebox.showinfo("Done", f"'{vt}' virus simulation created.")
        btn = tk.Button(generator, text=text, width=20, command=handle_generation)
        btn.pack(side="left", padx=10, pady=5)
        widgets.append(btn)
    scanner = tk.LabelFrame(window, text="🔍 Scan & Quarantine", padx=10, pady=10)
    scanner.pack(pady=10, padx=20, fill="x")
    widgets.append(scanner)

    folder_label = tk.Label(scanner, text="No folder selected.")
    folder_label.pack()
    widgets.append(folder_label)

    choose_btn = tk.Button(scanner, text="📂 Choose Folder", width=25,
                           command=lambda: choose_folder(folder_label))
    choose_btn.pack(pady=5)
    widgets.append(choose_btn)

    progress = Progressbar(scanner, length=600, style="green.Horizontal.TProgressbar", mode="indeterminate")
    progress.pack(pady=5)

    spinner_label = tk.Label(scanner, text="")
    spinner_label.pack()
    widgets.append(spinner_label)

    result_text = Text(scanner, height=12, width=85, wrap="word", bd=0)
    result_text.pack(pady=5)
    result_text.config(state="disabled")

    quarantine_btn = tk.Button(scanner, text="🔒 Quarantine Files", width=25, state=tk.DISABLED)
    quarantine_btn.pack(pady=3)
    widgets.append(quarantine_btn)

    scan_buttons = tk.Frame(scanner)
    scan_buttons.pack(pady=5)
    widgets.append(scan_buttons)

    local_btn = tk.Button(scan_buttons, text="🖥️ Scan Locally", width=25)
    vt_btn = tk.Button(scan_buttons, text="🌐 VirusTotal Scan", width=25)
    local_btn.pack(side="left", padx=10)
    vt_btn.pack(side="left", padx=10)
    widgets.extend([local_btn, vt_btn])

    def scan_local():
        def scan():
            global scanned_files, detected_files
            scanning = [True]
            threading.Thread(target=spinner_animation, args=(spinner_label, scanning), daemon=True).start()
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            scanned_files, detected_files = scan_folder_local(selected_folder, progress)
            scanning[0] = False
            spinner_label.config(text="")
            progress.stop()
            if detected_files:
                result_text.insert(tk.END, "🚨 Suspicious files:\n")
                for f, reasons in detected_files.items():
                    result_text.insert(tk.END, f"{f} — {', '.join(reasons)}\n")
                quarantine_btn.config(state=tk.NORMAL)
            else:
                result_text.insert(tk.END, "✅ No suspicious files found.")
                quarantine_btn.config(state=tk.DISABLED)
            result_text.config(state="disabled")
        progress.start(10)
        threading.Thread(target=scan).start()

    def scan_vt():
        def scan():
            global scanned_files
            scanning = [True]
            threading.Thread(target=spinner_animation, args=(spinner_label, scanning, "VirusTotal"), daemon=True).start()
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, "🦠 Sending files to VirusTotal...\n")
            result_text.config(state="disabled")
            scanned_files, results = scan_folder_virustotal(selected_folder, progress)
            scanning[0] = False
            spinner_label.config(text="")
            progress.stop()
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, "\n".join(results))
            result_text.config(state="disabled")
            quarantine_btn.config(state=tk.NORMAL)
        progress.start(10)
        threading.Thread(target=scan).start()

    def spinner_animation(label, flag, prefix="Scanning"):
        frames = ["|", "/", "-", "\\"]
        i = 0
        while flag[0]:
            label.config(text=f"{prefix}... {frames[i % 4]}")
            i += 1
            time.sleep(0.1)

    def quarantine_detected():
        global quarantine_path, quarantined_files
        if not detected_files:
            messagebox.showinfo("Info", "No suspicious files to quarantine.")
            return
        custom_path = filedialog.askdirectory(title="Select Quarantine Folder")
        if not custom_path:
            messagebox.showinfo("Cancelled", "No quarantine folder selected.")
            return
        quarantined = quarantine_files(selected_folder, list(detected_files.keys()), custom_path)
        quarantine_path = custom_path
        quarantined_files = list(detected_files.keys())
        messagebox.showinfo("Done", f"Files quarantined to: {quarantined}")
        quarantine_btn.config(state=tk.DISABLED)

    quarantine_btn.config(command=quarantine_detected)
    local_btn.config(command=scan_local)
    vt_btn.config(command=scan_vt)
    apply_theme(window, widgets, result_text, theme_mode, menu)
    window.mainloop()

if __name__ == "__main__":
    run_gui()
