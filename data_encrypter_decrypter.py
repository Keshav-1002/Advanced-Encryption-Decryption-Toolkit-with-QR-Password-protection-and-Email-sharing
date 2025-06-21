import random
import tkinter as tk
from tkinter import ttk, messagebox

def divide_string(input_str, length, key):
    if length < 4:
        messagebox.showerror("Error", "String is too short to divide into four parts.")
        return key
    
    part_length = length // 4
    num = random.randint(0, 9)
    key = key * 10 + num
    input_str = list(input_str)
    
    for i in range(part_length):
        input_str[i] = chr(ord(input_str[i]) ^ num)
    num = random.randint(0, 9)
    key = key * 10 + num
    for i in range(part_length, 2 * part_length):
        input_str[i] = chr(ord(input_str[i]) ^ num)
    num = random.randint(0, 9)
    
    key = key * 10 + num
    for i in range(2 * part_length, 3 * part_length):
        input_str[i] = chr(ord(input_str[i]) ^ num)
    num = random.randint(0, 9)
    key = key * 10 + num
    for i in range(3 * part_length, length):
        input_str[i] = chr(ord(input_str[i]) ^ num)
    return key, ''.join(input_str)


# converts string into cyber text
def enc_main(input_str):
    if len(input_str) < 4:
        messagebox.showerror("Error", "String is too short to be divided into four parts.")
        return
    
    length = len(input_str)
    key = 0
    j = 0
    k = length // 2
    for i in range(2):
        num = random.randint(0, 9)
        key = key * 10 + num
        while j < k:
            input_str = list(input_str)
            input_str[j] = chr(ord(input_str[j]) ^ num)
            j += 1
        input_str = ''.join(input_str)
        j = k
        k = length
        
    key, encrypted_str = divide_string(input_str, length, key)
    print(f"Encrypted String: {encrypted_str}\nKey: {key}")
    messagebox.showinfo("Encryption Complete", "Your message is encrypted. Now your data is safe.")
    kf=open(r"key.txt", "w") 
    f=open(r"data.txt", "w") 
    f.write(encrypted_str)
    kf.write(str(key))
    f.close()
    kf.close()


def decryption(input_str, length, key):
    part_length = length // 4
    input_str = list(input_str)
    for i in range(3, -1, -1):
        num = key % 10
        key //= 10
        for j in range(i * part_length, (i + 1) * part_length if i < 3 else length):
            input_str[j] = chr(ord(input_str[j]) ^ num)
    return key, ''.join(input_str)


def dec_main():
    try:    
        kf=open(r"C:\Users\Keshav Singhal\OneDrive - Graphic Era University\Desktop\Mini Project\Data Encrypter\key.txt", "r") 
        f=open(r"C:\Users\Keshav Singhal\OneDrive - Graphic Era University\Desktop\Mini Project\Data Encrypter\data.txt", "r") 
        key=int(kf.read())
        encrypted_str=f.read()
        length=len(encrypted_str)
        key, decrypted_str = decryption(encrypted_str, length, key)
        j = length // 2
        k = length
        for i in range(2):
            num = key % 10
            key //= 10
            while j < k:
                decrypted_str = list(decrypted_str)
                decrypted_str[j] = chr(ord(decrypted_str[j]) ^ num)
                j += 1
            decrypted_str = ''.join(decrypted_str)
            k = j // 2
            j = 0
        messagebox.showinfo("Decryption Complete", f"Decrypted Data:\n{decrypted_str}")
        print(f"Decrypted String: {decrypted_str}")
    except FileNotFoundError:
        messagebox.showwarning("File Not Found", "Encrypted data and key files not found. Please encrypt data first.")
    f.close()
    kf.close()        


# Create the main window
root = tk.Tk()
root.title("Data Encrypter")
root.configure(background="skyblue")
style = ttk.Style()

style.configure("TButton", padding=10, font=('Helvetica', 12), foreground="black", background="#4CAF50")

label = ttk.Label(root, text="Message Slider", foreground="#009688")
label.pack(pady=10)

data_entry = ttk.Entry(root, width=50)
data_entry.pack(pady=10)

encrypt_button = ttk.Button(root, text="Send Message", command=lambda: enc_main(data_entry.get()))
encrypt_button.pack(pady=10)

decrypt_button = ttk.Button(root, text="Receive Message", command=dec_main)
decrypt_button.pack(pady=10)
root.mainloop()
