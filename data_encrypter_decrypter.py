import random
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import winsound
import pyttsx3
import threading
from tkinter import simpledialog
import hashlib
import time
import smtplib
from email.message import EmailMessage
import re
import os
import webbrowser

mode = "dark"

class ToolTip:
    
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.x = self.y = 0
        widget.bind("<Enter>", self.schedule)
        widget.bind("<Leave>", self.unschedule)

    def schedule(self, event=None):
        self.unschedule()
        self.id = self.widget.after(500, self.show_tip)

    def unschedule(self, event=None):
        
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None
            
        self.hide_tip()

    def show_tip(self, event=None):
        
        if self.tip_window or not self.text:
            return
        
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tip_window = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = Label(tw, text=self.text, justify=LEFT, background="#FFFFE0", relief=SOLID, 
                    borderwidth=1, font=("Segoe UI", 9))
        label.pack(ipadx=6, ipady=2)

    def hide_tip(self):
        
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

def toggle_password_visibility():
    
    if show_password_var.get():
        password_entry.config(show="")
        
    else:
        password_entry.config(show="*")

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

def send_encrypted_email():
    
    try:
        sender_email = simpledialog.askstring("Sender Email", "Enter sender's Gmail address:")
        
        if not sender_email:
            return

        sender_password = simpledialog.askstring("App Password", "Enter sender's Gmail app password:", show="*")
        
        if not sender_password:
            return

        to_email = simpledialog.askstring("Recipient Email", "Enter recipient's email address:")
        
        if not to_email:
            return

        with open("data.txt", "r") as df, open("key.txt", "r") as kf:
            encrypted_data = df.read()
            encryption_key = kf.read()

        msg = EmailMessage()
        msg.set_content(
            f"Here is your encrypted data and key:\n\n"
            f"Encrypted Data:\n{encrypted_data}\n\n"
            f"Encryption Key:\n{encryption_key}"     )
        msg['Subject'] = "Encrypted Data"
        msg['From'] = sender_email
        msg['To'] = to_email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)

        speak("Email sent successfully.")
        messagebox.showinfo("Email Sent", f"Encrypted data sent to {to_email}.")
        log_activity(f"Encrypted data emailed from {sender_email} to: {to_email}")

    except Exception as e:
        play_error_sound()
        speak("Failed to send email.")
        messagebox.showerror("Email Error", f"Could not send email:\n\n{str(e)}")
        log_activity("Email failed: " + str(e))

def check_password_strength(password):
    style = ttk.Style()
    strength = 0

    if len(password) >= 6:
        strength += 1
        
    if re.search(r"\d", password):
        strength += 1
        
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        strength += 1
        
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1

    if strength <= 1:
        strength_label.config(text="Weak Password", fg="white", bg="red")
        style.configure("Red.Horizontal.TProgressbar", background="red", troughcolor="#ccc")
        strength_bar.configure(style="Red.Horizontal.TProgressbar")
        strength_bar["value"] = 25

    elif strength == 2 or strength == 3:
        strength_label.config(text="Medium Password", fg="black", bg="orange")
        style.configure("Yellow.Horizontal.TProgressbar", background="orange", troughcolor="#ccc")
        strength_bar.configure(style="Yellow.Horizontal.TProgressbar")
        strength_bar["value"] = 60

    else:
        strength_label.config(text="Strong Password", fg="white", bg="green")
        style.configure("Green.Horizontal.TProgressbar", background="green", troughcolor="#ccc")
        strength_bar.configure(style="Green.Horizontal.TProgressbar")
        strength_bar["value"] = 100

def enc_main():
    play_click_sound()
    input_str = data_entry.get()

    if len(input_str) < 4:
        play_error_sound()
        speak("String is too short to be divided into four parts.")
        messagebox.showerror("Error", "String is too short to be divided into four parts.")
        return

    password = password_entry.get()
    
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
        msg_id = str(int(time.time()))
        history_lines = []
        
        if os.path.exists("history.txt"):
            
            with open("history.txt", "r") as f:
                history_lines = f.readlines()

        history_lines.append(f"{msg_id}||{encrypted_str}||{key}||{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        history_lines = history_lines[-10:]

        with open("history.txt", "w") as f:
            f.writelines(history_lines)

        with open("passwords.txt", "a") as f:
            f.write(f"{msg_id}||{hashed_pass}\n")

        play_success_sound()
        speak("Your data is encrypted and safe.")
        messagebox.showinfo("Success", "Your message is encrypted.")
        log_activity("Encrypted: " + input_str)
        
        data_entry.delete(0, END)
        password_entry.delete(0, END)
        strength_bar["value"] = 0
        strength_bar.configure(style="Neutral.Horizontal.TProgressbar")
        strength_label.config(text="", fg="white", bg="#263238")
        
        preview_box.config(state=NORMAL)
        preview_box.delete(1.0, END)
        preview_box.insert(END, encrypted_str)
        preview_box.config(state=DISABLED)
        answer = messagebox.askyesno("Send Email", "Do you want to email the encrypted message and key?")
        
        if answer:
            send_encrypted_email()
            
        previous_combobox['values'] = load_history_items()
        previous_combobox.set("Select a previous encrypted message")

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

def decrypt_from_history(event):
    selected = previous_combobox.get()
    
    if not selected:
        return

    msg_id = selected.split(" | ")[0]
    entered_pass = simpledialog.askstring("Password Required", "Enter password for this message:", show="*")
    
    if not entered_pass:
        return

    try:
        pw_data = {}
        
        if os.path.exists("passwords.txt"):
            
            with open("passwords.txt", "r") as f:
                
                for line in f:
                    pid, pwhash = line.strip().split("||")
                    pw_data[pid] = pwhash

        history = []
        
        if os.path.exists("history.txt"):
            
            with open("history.txt", "r") as f:
                
                for line in f:
                    pid, msg, key, ts = line.strip().split("||")
                    history.append({
                    "id": pid,
                    "message": msg,
                    "key": key,
                    "timestamp": ts
                })


        if msg_id not in pw_data:
            messagebox.showerror("Error", "Password not found for selected message.")
            return

        if hash_password(entered_pass) != pw_data[msg_id]:
            play_error_sound()
            speak("Incorrect password.")
            messagebox.showerror("Error", "Incorrect password. Decryption aborted.")
            log_activity("Decryption failed from history: Incorrect password")
            return

        for entry in history:
            
            if entry['id'] == msg_id:
                key = int(entry['key'])
                encrypted_str = entry['message']
                break
            
        else:
            messagebox.showerror("Error", "Selected message not found.")
            return

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
        speak("Decryption complete from history.")
        type_writer_effect(decrypted_str)
        log_activity(f"Decrypted from history: {msg_id}")

    except Exception as e:
        play_error_sound()
        speak("Error during history decryption.")
        messagebox.showerror("Error", str(e))
        
    previous_combobox['values'] = load_history_items()

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
    about_window = Toplevel(root)
    about_window.title("About This Project")
    about_window.geometry("600x550")
    about_window.resizable(False, False)
    ToolTip(about_window, "This window provides details about the project.")
    
    bg_color = "#263238" if mode == "dark" else "white"
    fg_color = "white" if mode == "dark" else "black"
    text_bg = "#1E1E1E" if mode == "dark" else "#F0F0F0"
    
    about_window.configure(bg=bg_color)
    about_label = Label(about_window, text="🔐 Secure Data Encrypter & History Manager",
                    font=("Segoe UI", 13, "bold"), bg=bg_color, fg=fg_color)
    about_label.pack(pady=(10, 2))

    def open_github(event):
        webbrowser.open("https://github.com/Keshav-1002/Data-Encrypter-Decrypter")
        
    github_link = Label(about_window, text="🔗 GitHub: github.com/Keshav-1002/Data-Encrypter-Decrypter",
                font=("Segoe UI", 10, "underline"), fg="blue", bg=bg_color, cursor="hand2")
    github_link.pack()
    github_link.bind("<Button-1>", open_github)
    github_link.bind("<Enter>", lambda e: github_link.config(fg="purple"))
    github_link.bind("<Leave>", lambda e: github_link.config(fg="blue"))
    ToolTip(github_link, "Click to open the GitHub repository in your browser.")

    frame = Frame(about_window, bg=bg_color)
    frame.pack(expand=True, fill=BOTH, padx=10, pady=10)

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    about_text = Text(frame, wrap=WORD, font=("Segoe UI", 10), yscrollcommand=scrollbar.set, bg=text_bg,
                        fg=fg_color, relief=FLAT)
    about_text.insert(END, (
        "👨‍💻 Author: Keshav Singhal\n"
        "📫 GitHub: https://github.com/Keshav-1002/Data-Encrypter-Decrypter\n\n"
        "📘 Features:\n"
        "✔️ Encrypt messages with 2-phase XOR and random multi-digit key.\n"
        "✔️ Password-protected encryption using SHA-256 hashing.\n"
        "✔️ Password strength checker with live progress bar.\n"
        "✔️ Decrypt using current or historical encrypted messages.\n"
        "✔️ Stores only the last 10 encrypted messages with timestamps.\n"
        "✔️ Passwords stored securely in a separate file (hashed).\n"
        "✔️ Email encrypted message & key using Gmail SMTP.\n"
        "✔️ Dark/Light mode toggle.\n"
        "✔️ Sound and voice feedback using winsound and pyttsx3.\n"
        "✔️ Activity log window for user actions.\n\n"
        "📁 Files Used:\n"
        "- history.txt: Stores last 10 messages and keys.\n"
        "- passwords.txt: Stores hashed passwords.\n"
        "- key.txt, data.txt, pass.txt: Temporary use for current encryption.\n\n"
        "🎯 Instructions:\n"
        "- Enter message and password to encrypt.\n"
        "- Use 'Encrypt Message' to process and preview.\n"
        "- Use 'Decrypt Message' for current entry.\n"
        "- Use dropdown to select and decrypt from history.\n"
        "- Click 'Toggle Theme' to switch between light/dark mode.\n"
        "- Click 'Help > About' for this info.\n\n"
        "✅ Safe. Fast. Offline. Easy to Use."
    ))
    
    about_text.config(state=DISABLED)
    about_text.pack(fill=BOTH, expand=True)
    scrollbar.config(command=about_text.yview)

    close_btn = Button(about_window, text="Close", command=about_window.destroy,
                        bg="#4DB6AC" if mode == "dark" else "#AED581",
                        fg="white" if mode == "dark" else "black",
                        font=("Segoe UI", 10), padx=10, pady=5)
    close_btn.pack(pady=10)

root = Tk()
root.title("Secure Data Encrypter")
root.geometry("800x700")
root.configure(bg="#263238")

show_password_var = BooleanVar(value=False)

style = ttk.Style()
style.configure("Red.Horizontal.TProgressbar", troughcolor="#ccc", background="red")
style.configure("Yellow.Horizontal.TProgressbar", troughcolor="#ccc", background="orange")
style.configure("Green.Horizontal.TProgressbar", troughcolor="#ccc", background="green")
style.theme_use("clam")
style.configure("TButton", padding=10, font=('Segoe UI', 11), foreground="black", background="#AED581")
style.configure("Dark.TButton", padding=10, font=('Segoe UI', 11), foreground="white", background="#4DB6AC")
style.configure("Neutral.Horizontal.TProgressbar", troughcolor="#ccc", background="#888888")

label = Label(root, text="Message to Encrypt:", fg="white", bg="#263238", font=("Segoe UI", 12))
label.pack(pady=10)

data_entry = Entry(root, width=50, font=("Segoe UI", 11))
data_entry.pack(pady=10)
ToolTip(data_entry, "Enter your message here to encrypt.")

password_label = Label(root, text="Set Password:", fg="white", bg="#263238", font=("Segoe UI", 12))
password_label.pack(pady=(10, 0))

password_entry = Entry(root, width=50, font=("Segoe UI", 11), show="*")
password_entry.pack(pady=(0, 5))
password_entry.bind("<KeyRelease>", lambda e: check_password_strength(password_entry.get()))
ToolTip(password_entry, "Set a password for encrypting your message.")

show_password_check = Checkbutton(root, text="Show Password", variable=show_password_var,
    command=toggle_password_visibility, bg="#263238", fg="white", activebackground="#263238", 
    activeforeground="white", selectcolor="#263238" )
show_password_check.pack()
ToolTip(show_password_check, "Toggle visibility of the password.")

strength_label = Label(root, text="", font=("Segoe UI", 10), bg="#263238", fg="white")
strength_label.pack(pady=(2, 0))
ToolTip(strength_label, "Shows the strength of your entered password.")

strength_bar = ttk.Progressbar(root, length=200, mode='determinate', maximum=100, style="Red.Horizontal.TProgressbar")
strength_bar.pack(pady=5)
strength_bar["value"] = 0
ToolTip(strength_bar, "Progress bar for password strength (Weak/Medium/Strong).")

button_frame = Frame(root, bg="#263238")
button_frame.pack(pady=10)

encrypt_button = ttk.Button(button_frame, text="Encrypt Message", command=enc_main, style="Dark.TButton")
encrypt_button.grid(row=0, column=0, padx=10)
ToolTip(encrypt_button, "Encrypt the message with the provided password.")

decrypt_button = ttk.Button(button_frame, text="Decrypt Message", command=dec_main, style="Dark.TButton")
decrypt_button.grid(row=0, column=1, padx=10)
ToolTip(decrypt_button, "Decrypt the most recent encrypted message.")

history_label = Label(root, text="Previous Encrypted Messages:", fg="white", bg="#263238", font=("Segoe UI", 11))
history_label.pack(pady=(10, 0))
ToolTip(history_label, "Shows the last 10 encrypted messages.")

previous_combobox = ttk.Combobox(root, state="readonly", font=("Segoe UI", 10), width=60)
previous_combobox.pack(pady=5)

def load_history_items():
    items = []
    
    if os.path.exists("history.txt"):
        
        with open("history.txt", "r") as f:
            lines = f.readlines()
            
            for line in reversed(lines):
                
                try:
                    parts = line.strip().split("||")
                    
                    if len(parts) >= 4:
                        msg_id = parts[0]
                        timestamp = parts[-1]  # safely get the last part
                        items.append(f"{msg_id} | {timestamp}")
                        
                except Exception:
                    continue
                
    return items

previous_combobox['values'] = load_history_items()
previous_combobox.bind("<<ComboboxSelected>>", decrypt_from_history)
ToolTip(previous_combobox, "Select and decrypt an older encrypted message.")

toggle_button = ttk.Button(root, text="Toggle Theme", command=toggle_theme, style="Dark.TButton")
toggle_button.pack(pady=10)
ToolTip(toggle_button, "Switch between Dark and Light theme.")

preview_label = Label(root, text="Encrypted Preview:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
preview_label.pack(pady=(10, 0))
ToolTip(preview_label, "Preview of the encrypted message.")

preview_box = Text(root, height=4, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
preview_box.pack(pady=5)
preview_box.config(state=DISABLED)
ToolTip(preview_box, "This area shows the encrypted message.")

decrypted_label = Label(root, text="Decrypted Output:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
decrypted_label.pack(pady=(10, 0))
ToolTip(decrypted_label, "Decrypted message will appear here.")

decrypted_display = Text(root, height=4, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
decrypted_display.pack(pady=5)
decrypted_display.config(state=DISABLED)
ToolTip(decrypted_display, "This area displays the decrypted output.")

log_label = Label(root, text="Activity Log:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
log_label.pack(pady=(10, 0))
ToolTip(log_label, "Track your encryption and decryption actions here.")

log_box = Text(root, height=6, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
log_box.pack(pady=5)
ToolTip(log_box, "Shows activity logs for encryption/decryption actions.")

data_entry.focus_set()
data_entry.bind("<Return>", lambda e: enc_main())

menubar = Menu(root)
help_menu = Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menubar)

root.mainloop()
