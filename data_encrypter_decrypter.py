import random
from tkinter import *
from tkinter import messagebox, ttk
import winsound
import pyttsx3
import threading
from tkinter import simpledialog
import hashlib
import time

mode = "dark"

def speak(text):
    def run():
        engine = pyttsx3.init()
        engine.setProperty('rate', 160)
        engine.say(text)
        engine.runAndWait()
        engine.stop()
    threading.Thread(target=run, daemon=True).start()

def play_click_sound():
    winsound.Beep(800, 75)

def play_success_sound():
    winsound.Beep(1000, 150)

def play_error_sound():
    winsound.Beep(400, 250)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def divide_string(input_str, length, key):
    if length < 4:
        play_error_sound()
        speak("String is too short to divide into four parts.")
        messagebox.showerror("Error", "String is too short to divide into four parts.")
        return key, input_str

    part_length = length // 4
    input_str = list(input_str)

    for _ in range(4):
        num = random.randint(0, 9)
        key = key * 10 + num
        start = _ * part_length
        end = (start + part_length) if _ < 3 else length
        for i in range(start, end):
            input_str[i] = chr(ord(input_str[i]) ^ num)

    return key, ''.join(input_str)

def type_writer_effect(output_text):
    decrypted_display.config(state=NORMAL)
    decrypted_display.delete(1.0, END)
    for i in range(len(output_text) + 1):
        decrypted_display.delete(1.0, END)
        decrypted_display.insert(END, output_text[:i])
        root.update()
        time.sleep(0.05)
    decrypted_display.config(state=DISABLED)

def enc_main():
    play_click_sound()
    input_str = data_entry.get()

    if len(input_str) < 4:
        play_error_sound()
        speak("String is too short to be divided into four parts.")
        messagebox.showerror("Error", "String is too short to be divided into four parts.")
        return

    password = simpledialog.askstring("Set Password", "Enter password for encryption:", show="*")
    if not password:
        play_error_sound()
        speak("Encryption cancelled. No password entered.")
        log_activity("Encryption cancelled: No password entered")
        return

    hashed_pass = hash_password(password)
    log_activity("Password set for encryption.")

    key = 0
    j = 0
    k = len(input_str) // 2
    input_list = list(input_str)

    for _ in range(2):
        num = random.randint(0, 9)
        key = key * 10 + num
        while j < k:
            input_list[j] = chr(ord(input_list[j]) ^ num)
            j += 1
        j = k
        k = len(input_list)

    temp_input = ''.join(input_list)
    key, encrypted_str = divide_string(temp_input, len(temp_input), key)

    try:
        with open("key.txt", "w") as kf, open("data.txt", "w") as f, open("pass.txt", "w") as pf:
            kf.write(str(key))
            f.write(encrypted_str)
            pf.write(hashed_pass)

        play_success_sound()
        speak("Your data is encrypted and safe.")
        messagebox.showinfo("Success", "Your message is encrypted.")
        log_activity("Encrypted: " + input_str)
        data_entry.delete(0, END)
        preview_box.config(state=NORMAL)
        preview_box.delete(1.0, END)
        preview_box.insert(END, encrypted_str)
        preview_box.config(state=DISABLED)

    except Exception as e:
        play_error_sound()
        speak("Error writing to file.")
        messagebox.showerror("File Error", str(e))

def decryption(input_str, length, key):
    part_length = length // 4
    input_str = list(input_str)

    for i in range(3, -1, -1):
        num = key % 10
        key //= 10
        start = i * part_length
        end = (i + 1) * part_length if i < 3 else length
        for j in range(start, end):
            input_str[j] = chr(ord(input_str[j]) ^ num)

    return key, ''.join(input_str)

def dec_main():
    play_click_sound()

    try:
        with open("key.txt", "r") as kf, open("data.txt", "r") as f, open("pass.txt", "r") as pf:
            key = int(kf.read())
            encrypted_str = f.read()
            saved_pass = pf.read()
    except FileNotFoundError:
        play_error_sound()
        speak("Required files not found.")
        messagebox.showwarning("Missing Files", "Encrypted data or key not found.")
        return
    except Exception as e:
        play_error_sound()
        speak("Error reading files.")
        messagebox.showerror("Error", str(e))
        return

    entered_pass = simpledialog.askstring("Password", "Enter decryption password:", show="*")
    if not entered_pass or hash_password(entered_pass) != saved_pass:
        play_error_sound()
        speak("Incorrect password.")
        messagebox.showerror("Error", "Incorrect password. Decryption aborted.")
        log_activity("Decryption failed: Incorrect password")
        return

    log_activity("Password correct. Proceeding with decryption.")

    length = len(encrypted_str)
    key, decrypted_str = decryption(encrypted_str, length, key)

    j = length // 2
    k = length
    for _ in range(2):
        num = key % 10
        key //= 10
        decrypted_str = list(decrypted_str)
        while j < k:
            decrypted_str[j] = chr(ord(decrypted_str[j]) ^ num)
            j += 1
        decrypted_str = ''.join(decrypted_str)
        k = j // 2
        j = 0

    play_success_sound()
    speak("Your data is decrypted successfully.")
    type_writer_effect(decrypted_str)
    log_activity("Decrypted: " + decrypted_str)
    data_entry.delete(0, END)

def log_activity(action):
    log_box.insert(END, action + "\n")
    log_box.see(END)

def toggle_theme():
    global mode
    if mode == "dark":
        mode = "light"
        root.configure(bg="white")
        label.configure(bg="white", fg="black")
        encrypt_button.configure(style="TButton")
        decrypt_button.configure(style="TButton")
        toggle_button.configure(style="TButton")
        log_box.configure(bg="#F0F0F0", fg="black")
        log_label.configure(bg="white", fg="black")
        preview_box.configure(bg="#F0F0F0", fg="black")
        preview_label.configure(bg="white", fg="black")
        decrypted_display.configure(bg="#F0F0F0", fg="black")
        decrypted_label.configure(bg="white", fg="black")
        log_activity("Theme changed to Light Mode")
    else:
        mode = "dark"
        root.configure(bg="#263238")
        label.configure(bg="#263238", fg="white")
        encrypt_button.configure(style="Dark.TButton")
        decrypt_button.configure(style="Dark.TButton")
        toggle_button.configure(style="Dark.TButton")
        log_box.configure(bg="#1E1E1E", fg="white")
        log_label.configure(bg="#263238", fg="white")
        preview_box.configure(bg="#1E1E1E", fg="white")
        preview_label.configure(bg="#263238", fg="white")
        decrypted_display.configure(bg="#1E1E1E", fg="white")
        decrypted_label.configure(bg="#263238", fg="white")
        log_activity("Theme changed to Dark Mode")

def show_about():
    about_text = (
        "🔐 Secure Data Encrypter\n"
        "\n"
        "👨‍💻 Author: Keshav Singhal\n"
        "📫 GitHub: https://github.com/Keshav-1002/Data-Encrypter-Decrypter\n"
        "\n"
        "📘 Instructions:\n"
        "- Enter a message to encrypt.\n"
        "- Click 'Encrypt Message' to save encrypted data.\n"
        "- Use 'Decrypt Message' to recover it.\n"
        "- Toggle between Light/Dark themes.\n"
        "- All encryption keys are stored in 'key.txt'.\n"
        "- Encrypted messages are saved in 'data.txt'.\n"
        "- Voice and sound feedback included."
    )
    messagebox.showinfo("About This Project", about_text)

root = Tk()
root.title("Secure Data Encrypter")
root.geometry("600x700")
root.configure(bg="#263238")

style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", padding=10, font=('Segoe UI', 11), foreground="black", background="#AED581")
style.configure("Dark.TButton", padding=10, font=('Segoe UI', 11), foreground="white", background="#4DB6AC")

label = Label(root, text="Message to Encrypt:", fg="white", bg="#263238", font=("Segoe UI", 12))
label.pack(pady=10)

data_entry = Entry(root, width=50, font=("Segoe UI", 11))
data_entry.pack(pady=10)

button_frame = Frame(root, bg="#263238")
button_frame.pack(pady=10)

encrypt_button = ttk.Button(button_frame, text="Encrypt Message", command=enc_main, style="Dark.TButton")
encrypt_button.grid(row=0, column=0, padx=10)

decrypt_button = ttk.Button(button_frame, text="Decrypt Message", command=dec_main, style="Dark.TButton")
decrypt_button.grid(row=0, column=1, padx=10)

toggle_button = ttk.Button(root, text="Toggle Theme", command=toggle_theme, style="Dark.TButton")
toggle_button.pack(pady=10)

preview_label = Label(root, text="Encrypted Preview:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
preview_label.pack(pady=(10, 0))

preview_box = Text(root, height=4, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
preview_box.pack(pady=5)
preview_box.config(state=DISABLED)

decrypted_label = Label(root, text="Decrypted Output:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
decrypted_label.pack(pady=(10, 0))

decrypted_display = Text(root, height=4, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
decrypted_display.pack(pady=5)
decrypted_display.config(state=DISABLED)

log_label = Label(root, text="Activity Log:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
log_label.pack(pady=(10, 0))

log_box = Text(root, height=6, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
log_box.pack(pady=5)

data_entry.focus_set()
data_entry.bind("<Return>", lambda e: enc_main())

menubar = Menu(root)
help_menu = Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menubar)

root.mainloop()
