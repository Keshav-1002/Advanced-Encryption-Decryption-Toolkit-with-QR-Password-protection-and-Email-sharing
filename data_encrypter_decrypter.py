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
import re
import os
import webbrowser
import qrcode
from PIL import Image
from PIL import ImageTk
import json
from pyzbar.pyzbar import decode
import cv2
from tkinter import filedialog
from email.message import EmailMessage

themed_widgets = []
mode = "dark"
engine = pyttsx3.init()
speech_lock = threading.Lock()

def open_review_link():
    review_url = "https://forms.gle/HaujdagXXmimMqkh7"
    webbrowser.open_new_tab(review_url)
    log_activity("Opened review/feedback link from About window.")
    speak("Opening review link.")
    
def generate_qr_code():
    encrypted_data = preview_box.get("1.0", END).strip()

    if not encrypted_data:
        play_error_sound()
        speak("No encrypted data found to generate QR code.")
        messagebox.showwarning("No Data", "No encrypted message found in preview.")
        return

    try:
        
        with open("history.txt", "r") as hf:
            last_line = hf.readlines()[-1]
            msg_id, encrypted_data, key, timestamp = last_line.strip().split("||")

        qr_data = {
            "data": encrypted_data,
            "key": key,
            "msg_id": msg_id
        }

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        
        qr.add_data(json.dumps(qr_data))
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        qr_window = Toplevel(root)
        qr_window.title("Encrypted Message - QR Code")
        qr_window.geometry("800x800")
        qr_window.resizable(False, False)

        img.save("qrcode.png")

        qr_img = Image.open("qrcode.png")
        qr_tk = ImageTk.PhotoImage(qr_img)
        label = Label(qr_window, image=qr_tk)
        label.image = qr_tk
        label.pack(pady=10)

        save_btn = Button(qr_window, text="Save QR Code", font=("Segoe UI", 10),
                        command=lambda: img.save("EncryptedMessageQR.png"))
        save_btn.pack(pady=5)

        close_btn = Button(qr_window, text="Close", font=("Segoe UI", 10), command=qr_window.destroy)
        close_btn.pack(pady=5)

        log_activity("QR code generated for encrypted message.")
        speak("QR code with password protection generated.")

    except Exception as e:
        play_error_sound()
        speak("Error generating QR code.")
        messagebox.showerror("QR Code Error", str(e))

def decrypt_qr_code():
    play_click_sound()
    file_path = filedialog.askopenfilename(title="Select QR Code Image",
                                           filetypes=[("Image Files", "*.png *.jpg *.jpeg")])
    
    if not file_path:
        return

    try:
        img = cv2.imread(file_path)
        decoded_objs = decode(img)

        if not decoded_objs:
            play_error_sound()
            speak("No QR code found in the image.")
            messagebox.showerror("Error", "No QR code found.")
            return

        qr_data = json.loads(decoded_objs[0].data.decode("utf-8"))

        encrypted_str = qr_data.get("data")
        key = int(qr_data.get("key"))
        msg_id = qr_data.get("msg_id")

        if not encrypted_str or not key or not msg_id:
            raise ValueError("Incomplete QR data")

        entered_pass = simpledialog.askstring("Password", "Enter password for QR message:", show="*")
        
        if not entered_pass:
            return

        password_valid = False
        
        if os.path.exists("passwords.txt"):
            
            with open("passwords.txt", "r") as f:
                
                for line in f:
                    pid, pwhash = line.strip().split("||")
                    
                    if pid == msg_id and hash_password(entered_pass) == pwhash:
                        password_valid = True
                        break

        if not password_valid:
            play_error_sound()
            speak("Incorrect password.")
            messagebox.showerror("Access Denied", "Incorrect password. Decryption failed.")
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
        speak("QR message decrypted successfully.")
        type_writer_effect(decrypted_str)
        log_activity("Decrypted from QR Code.")

    except Exception as e:
        play_error_sound()
        speak("Error during QR code decryption.")
        messagebox.showerror("Error", str(e))

class ToolTip:
    
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.x = self.y = 0
        widget.bind("<Enter>", self.schedule, add="+")
        widget.bind("<Leave>", self.unschedule, add="+")

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

def speak(msg):
    def run():
        with speech_lock:
            engine.say(msg)
            engine.runAndWait()
    threading.Thread(target=run).start()

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

def send_encrypted_email(include_qr=False, include_text=False):
    
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

        msg = EmailMessage()
        body = ""

        if include_text:
            
            with open("data.txt", "r") as df, open("key.txt", "r") as kf:
                encrypted_data = df.read()
                encryption_key = kf.read()
                
            body += f"Here is your encrypted data and key:\n\nEncrypted Data:\n{encrypted_data}\nEncryption Key:\n{encryption_key}\n\n"

        if not body:
            body = "QR code attached as requested."

        msg.set_content(body)
        msg['Subject'] = "Your Secure Data"
        msg['From'] = sender_email
        msg['To'] = to_email

        if include_qr and os.path.exists("qrcode.png"):
            
            with open("qrcode.png", "rb") as f:
                qr_data = f.read()
                msg.add_attachment(qr_data, maintype="image", subtype="png", filename="EncryptedMessageQR.png")

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)

        speak("Email sent successfully.")
        messagebox.showinfo("Email Sent", f"Your data was sent to {to_email}.")
        log_activity(f"Encrypted data emailed to {to_email}. Options - QR: {include_qr}, Text: {include_text}")

    except Exception as e:
        play_error_sound()
        speak("Failed to send email.")
        messagebox.showerror("Email Error", f"Could not send email:\n\n{str(e)}")
        log_activity("Email failed: " + str(e))

def ask_email_options():
    choice = messagebox.askquestion("Send Email", "Send Encrypted Message + Key + QR code?")
    
    if choice == "yes":
        send_encrypted_email(include_qr=True, include_text=True)
        
    else:
        choice2 = messagebox.askyesnocancel("Send Email", "Send only QR code?")
        
        if choice2 is True:
            send_encrypted_email(include_qr=True, include_text=False)
            
        elif choice2 is False:
            send_encrypted_email(include_qr=False, include_text=True)

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
        ask_email_options()
            
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
    mode = "light" if mode == "dark" else "dark"
    bg_color = "white" if mode == "light" else "#263238"
    fg_color = "black" if mode == "light" else "white"
    textbox_bg = "#F0F0F0" if mode == "light" else "#1E1E1E"

    root.configure(bg=bg_color)

    for widget in themed_widgets:
        
        if isinstance(widget, Text):
            widget.configure(bg=textbox_bg, fg=fg_color)
            
        else:
            widget.configure(bg=bg_color, fg=fg_color)

    style = ttk.Style()
    
    if mode == "light":
        style.configure("TButton", background="#AED581", foreground="black")
        style.configure("Dark.TButton", background="#AED581", foreground="black")
        
    else:
        style.configure("Dark.TButton", background="#4DB6AC", foreground="white")
        style.configure("TButton", background="#4DB6AC", foreground="white")

    log_activity(f"Theme changed to {'Light' if mode == 'light' else 'Dark'} Mode")

def show_about():
    about_window = Toplevel(root)
    about_window.title("About This Project")
    about_window.geometry("600x550")
    about_window.resizable(False, False)
    ToolTip(about_window, "This window provides details about the project.")

    bg_color = "#263238" if mode == "dark" else "white"
    fg_color = "white" if mode == "dark" else "black"
    text_bg = "#1E1E1E" if mode == "dark" else "#F0F0F0"
    link_normal_color = "blue"
    link_hover_color = "lightblue" if mode == "dark" else "purple"

    about_window.configure(bg=bg_color)
    about_label = Label(about_window, text="🔐 Secure Data Encrypter & History Manager",
                        font=("Segoe UI", 13, "bold"), bg=bg_color, fg=fg_color)
    about_label.pack(pady=(10, 2))

    def open_github(event):
        webbrowser.open("https://github.com/Keshav-1002/Data-Encrypter-Decrypter")

    github_link = Label(about_window, text="🔗 GitHub: github.com/Keshav-1002/Data-Encrypter-Decrypter",
    font=("Segoe UI", 10, "underline"), fg=link_normal_color, bg=bg_color, cursor="hand2",
    activeforeground=link_hover_color )
    github_link.pack()

    def on_hover_enter(event):
        event.widget.config(fg=link_hover_color, font=("Segoe UI", 10, "underline"))

    def on_hover_leave(event):
        event.widget.config(fg=link_normal_color, font=("Segoe UI", 10, "underline"))

    github_link.bind("<Enter>", on_hover_enter)
    github_link.bind("<Leave>", on_hover_leave)
    github_link.bind("<Button-1>", open_github)

    ToolTip(github_link, "Click to open the GitHub repository in your browser.")

    frame = Frame(about_window, bg=bg_color)
    frame.pack(expand=True, fill=BOTH, padx=10, pady=10)

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    about_text = Text(frame, wrap=WORD, font=("Segoe UI", 10), yscrollcommand=scrollbar.set, bg=text_bg,
                        fg=fg_color, relief=FLAT)
    about_text.config(state=NORMAL)

    about_text.insert(END, (
        "👨‍💻 Author: Keshav Singhal\n"
        "📫 GitHub: https://github.com/Keshav-1002/Data-Encrypter-Decrypter\n\n"

        "📘 Features:\n"
        "✔️ Encrypt messages using dual-phase XOR and random multi-digit key.\n"
        "✔️ Password-protected encryption using SHA-256 hashing.\n"
        "✔️ Real-time password strength checker with visual progress bar.\n"
        "✔️ Store only the last 10 encrypted messages with timestamps.\n"
        "✔️ Secure password storage (hashed) in a separate file.\n"
        "✔️ Email options:\n"
        "   • Encrypted message + key\n"
        "   • Only QR code\n"
        "   • Both (message + QR)\n"
        "✔️ QR code generation for encrypted messages.\n"
        "✔️ Password-protected QR code decryption.\n"
        "✔️ Spell Checker with Suggestions\n"
        "✔️ Context menu for spell suggestions in the message entry box.\n"
        "✔️ Typewriter effect for decrypted message display.\n"
        "✔️ Interactive User Feedback"
        "✔️ Decrypt using current or previous (history) messages.\n"
        "✔️ Combobox-based selection for decrypting from history.\n"
        "✔️ Light/Dark mode toggle with themed widget system.\n"
        "✔️ Activity log tracking all encryption, decryption, and email events.\n"
        "✔️ Sound and speech feedback using winsound and pyttsx3.\n"
        "✔️ GitHub link with hover effect and tooltip.\n"
        '''💡 Try typing secret educational keywords like “encryptiontip” or “hashing101” in the message 
                box to learn quick facts!\n\n'''

        "📁 Files Used:\n"
        "- history.txt: Stores last 10 encrypted messages and keys.\n"
        "- passwords.txt: Stores hashed passwords mapped to message IDs.\n"
        "- qrcode.png: Temporary QR image used for sharing.\n"
        "- key.txt, data.txt, pass.txt: Temporary storage for last encryption.\n\n"

        "🎯 Instructions:\n"
        "- Enter your message and set a strong password.\n"
        "- Click 'Encrypt Message' to encrypt and preview the result.\n"
        "- Generate QR code if needed.\n"
        "- Choose whether to send the encrypted message, QR, or both via email.\n"
        "- Decrypt using the latest message, QR image, or a history entry.\n"
        "- Use 'Toggle Theme' to switch between dark/light modes.\n"
        "- View logs and GitHub link in the bottom sections.\n\n"

        "✅ Secure. Offline. User-Friendly. Feature-Rich."
        ))

    about_text.config(state=DISABLED)
    about_text.pack(fill=BOTH, expand=True)
    scrollbar.config(command=about_text.yview)

    button_bottom_frame = Frame(about_window, bg=bg_color)
    button_bottom_frame.pack(pady=10) 

    rate_us_button = Button(button_bottom_frame, text="Rate Us!", command=open_review_link,
                            bg="#4DB6AC" if mode == "dark" else "#AED581",
                            fg="white" if mode == "dark" else "black",
                            font=("Segoe UI", 10), padx=10, pady=5)
    rate_us_button.pack(side=LEFT, padx=5)
    ToolTip(rate_us_button, "Click to leave a review or give feedback.")


    close_btn = Button(button_bottom_frame, text="Close", command=about_window.destroy,
                        bg="#4DB6AC" if mode == "dark" else "#AED581",
                        fg="white" if mode == "dark" else "black",
                        font=("Segoe UI", 10), padx=10, pady=5)
    close_btn.pack(side=RIGHT, padx=5) 

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
label.pack(pady=(5,5))
themed_widgets.append(label)

data_entry = Entry(root, width=50, font=("Segoe UI", 11))
data_entry.pack(pady=7)
ToolTip(data_entry, '''Enter your message here. \nTry keywords like 'encryptiontip', 'hashing101', 
        'xorinfo', or 'keshavrules' for hidden insights.''')

password_label = Label(root, text="Set Password:", fg="white", bg="#263238", font=("Segoe UI", 12))
password_label.pack(pady=(5, 0))
themed_widgets.append(password_label)

password_entry = Entry(root, width=50, font=("Segoe UI", 11), show="*")
password_entry.pack(pady=(0, 5))
password_entry.bind("<KeyRelease>", lambda e: check_password_strength(password_entry.get()))
ToolTip(password_entry, "Set a password for encrypting your message.")

show_password_check = Checkbutton(root, text="Show Password", variable=show_password_var,
    command=toggle_password_visibility, bg="#263238", fg="white", activebackground="#263238", 
    activeforeground="white", selectcolor="#263238" )
show_password_check.pack()
themed_widgets.append(show_password_check)
ToolTip(show_password_check, "Toggle visibility of the password.")

strength_label = Label(root, text="", font=("Segoe UI", 10), bg="#263238", fg="white")
strength_label.pack(pady=(2, 0))
themed_widgets.append(strength_label)
ToolTip(strength_label, "Shows the strength of your entered password.")

strength_bar = ttk.Progressbar(root, length=200, mode='determinate', maximum=100, style="Red.Horizontal.TProgressbar")
strength_bar.pack(pady=5)
strength_bar["value"] = 0
ToolTip(strength_bar, "Progress bar for password strength (Weak/Medium/Strong).")

button_frame = Frame(root, bg="#263238")
button_frame.pack(pady=7)

encrypt_button = ttk.Button(button_frame, text="Encrypt Message", command=enc_main, style="Dark.TButton")
encrypt_button.grid(row=0, column=0, padx=10)
ToolTip(encrypt_button, "Encrypt the message with the provided password.")

decrypt_button = ttk.Button(button_frame, text="Decrypt Message", command=dec_main, style="Dark.TButton")
decrypt_button.grid(row=0, column=1, padx=10)
ToolTip(decrypt_button, "Decrypt the most recent encrypted message.")

history_label = Label(root, text="Previous Encrypted Messages:", fg="white", bg="#263238", font=("Segoe UI", 11))
history_label.pack(pady=(7, 0))
themed_widgets.append(history_label)
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

toggle_button = ttk.Button(button_frame, text="Toggle Theme", command=toggle_theme, style="Dark.TButton")
toggle_button.grid(row=0, column=2, pady=10)
ToolTip(toggle_button, "Switch between Dark and Light theme.")

preview_label = Label(root, text="Encrypted Preview:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
preview_label.pack(pady=(10, 0))
ToolTip(preview_label, "Preview of the encrypted message.")
themed_widgets.append(preview_label)

preview_box = Text(root, height=4, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
preview_box.pack(pady=5)
preview_box.config(state=DISABLED)
themed_widgets.append(preview_box)
ToolTip(preview_box, "This area shows the encrypted message.")

qr_frame = Frame(root, bg="#263238")
qr_frame.pack(pady=10)

qr_button = ttk.Button(qr_frame, text="Generate QR Code", command=generate_qr_code, style="Dark.TButton")
qr_button.grid(row=0, column=0, padx=10)

qr_decode_button = ttk.Button(qr_frame, text="Decrypt from QR Code", command=decrypt_qr_code, style="Dark.TButton")
qr_decode_button.grid(row=0, column=1, padx=10)
ToolTip(qr_decode_button, "Scan QR image, enter password to decrypt the message.")

decrypted_label = Label(root, text="Decrypted Output:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
decrypted_label.pack(pady=(10, 0))
themed_widgets.append(decrypted_label)
ToolTip(decrypted_label, "Decrypted message will appear here.")

decrypted_display = Text(root, height=4, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
decrypted_display.pack(pady=5)
decrypted_display.config(state=DISABLED)
themed_widgets.append(decrypted_display)
ToolTip(decrypted_display, "This area displays the decrypted output.")

log_label = Label(root, text="Activity Log:", fg="white", bg="#263238", font=("Segoe UI", 11, "bold"))
log_label.pack(pady=(10, 0))
themed_widgets.append(log_label)
ToolTip(log_label, "Track your encryption and decryption actions here.")

log_box = Text(root, height=6, width=70, font=("Courier New", 10), bg="#1E1E1E", fg="white")
log_box.pack(pady=5)
themed_widgets.append(log_box)
ToolTip(log_box, "Shows activity logs for encryption/decryption actions.")

data_entry.focus_set()
data_entry.bind("<Return>", lambda e: enc_main())

menubar = Menu(root)
help_menu = Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menubar)

root.mainloop()
