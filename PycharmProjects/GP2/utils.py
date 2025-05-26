import os
import shutil
import webbrowser
from tkinter import filedialog

def save_quarantine_info(quarantine_path, files):
    with open("quarantine_info.txt", "w") as file:
        file.write(f"{quarantine_path}\n")
        for f in files:
            file.write(f"{f}\n")

def load_quarantine_info():
    if os.path.exists("quarantine_info.txt"):
        with open("quarantine_info.txt", "r") as file:
            lines = file.readlines()
            if lines:
                quarantine_path = lines[0].strip()
                files = [line.strip() for line in lines[1:]]
                return quarantine_path, files
    return "", []

def generate_virus_by_type(vtype, folder="simulated_virus"):
    os.makedirs(folder, exist_ok=True)

    if vtype == "beeper":
        script_path = os.path.join(folder, "beep_simulation.py")
        with open(script_path, 'w') as f:
            f.write("""import time
for _ in range(5):
    print("Beep!")
    time.sleep(1)
""")

    elif vtype == "message_spam":
        script_path = os.path.join(folder, "message_spam.py")
        with open(script_path, 'w') as f:
            f.write("""import tkinter as tk
from tkinter import messagebox
root = tk.Tk()
root.withdraw()
for _ in range(10):
    messagebox.showinfo("Alert", "YOU HAVE BEEN HACKED")
""")

    elif vtype == "eicar":
        # Official EICAR test file string exactly as per standard
        eicar_string = (
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        script_path = os.path.join(folder, "eicar_test_file.com")
        with open(script_path, 'w') as f:
            f.write(eicar_string)

    else:
        with open(os.path.join(folder, "unknown_fake.txt"), 'w') as f:
            f.write("Unknown virus type generated.")

def quarantine_files(base_folder, file_list, quarantine_path):
    os.makedirs(quarantine_path, exist_ok=True)
    for file in file_list:
        src = os.path.join(base_folder, file)
        dst = os.path.join(quarantine_path, file)
        try:
            if os.path.isfile(src):
                shutil.move(src, dst)
        except Exception as e:
            print(f"Error moving {file}: {e}")
    save_quarantine_info(quarantine_path, file_list)
    return quarantine_path

def move_quarantined_files(current_quarantine_path, new_quarantine_path, quarantined_files):
    os.makedirs(new_quarantine_path, exist_ok=True)
    for item in os.listdir(current_quarantine_path):
        src = os.path.join(current_quarantine_path, item)
        dst = os.path.join(new_quarantine_path, item)
        try:
            if os.path.isfile(src):
                shutil.move(src, dst)
            elif os.path.isdir(src):
                shutil.move(src, dst)
        except Exception as e:
            print(f"Error moving {item} to new path: {e}")

def open_folder(path):
    if os.path.exists(path):
        webbrowser.open(path)

def log_quarantine(folder, files):
    log_path = os.path.join(folder, "quarantine_log.txt")
    with open(log_path, "w") as log:
        for f in files:
            log.write(f"{f}\n")
