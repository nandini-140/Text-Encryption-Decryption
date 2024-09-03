from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import base64
import pyotp  # Import the TOTP library

# Generate a TOTP secret for 2FA (this would typically be done once and stored securely)
totp_secret = pyotp.random_base32()

def derive_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(message, password):
    key, salt = derive_key(password)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    return base64.b64encode(salt + iv + encryptor.tag + encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, password):
    try:
        data = base64.b64decode(encrypted_message)
        salt, iv, tag, ciphertext = data[:16], data[16:28], data[28:44], data[44:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        
        return message.decode()
    
    except (InvalidSignature, ValueError) as e:
        messagebox.showerror("Decryption Error", "Invalid password or corrupted data.")
        return None

def verify_2fa_code(code):
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code)

def decrypt():
    password = code.get()
    otp = otp_code.get()
    
    if password and otp:
        if verify_2fa_code(otp):
            screen2 = Toplevel(screen)
            screen2.title("Decryption")
            screen2.geometry("400x200")
            screen2.configure(bg="#00bd56")
            
            encrypted_message = text1.get(1.0, END).strip()
            
            decrypted_message = decrypt_message(encrypted_message, password)
            
            if decrypted_message:
                Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
                text2 = Text(screen2, font="Arial 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
                text2.place(x=10, y=40, width=380, height=150)
                text2.insert(END, decrypted_message)
            else:
                screen2.destroy()
        else:
            messagebox.showerror("2FA Error", "Invalid 2FA code.")
    else:
        messagebox.showerror("Decryption", "Please enter the password and 2FA code.")

def encrypt():
    password = code.get()
    otp = otp_code.get()

    if password and otp:
        if verify_2fa_code(otp):
            screen1 = Toplevel(screen)
            screen1.title("Encryption")
            screen1.geometry("400x200")
            screen1.configure(bg="#ed3833")
            
            message = text1.get(1.0, END).strip()
            
            encrypted_message = encrypt_message(message, password)
            
            Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
            text2 = Text(screen1, font="Arial 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, encrypted_message)
        else:
            messagebox.showerror("2FA Error", "Invalid 2FA code.")
    else:
        messagebox.showerror("Encryption", "Please enter the password and 2FA code.")

def display_totp_secret():
    totp = pyotp.TOTP(totp_secret)
    qr_code_url = totp.provisioning_uri(name="EncryptionApp", issuer_name="YourCompany")
    
    messagebox.showinfo("TOTP Setup", f"Scan this QR code or enter this secret key into your TOTP app: {totp_secret}")

def main_screen():
    global screen
    global code
    global text1
    global otp_code
    
    screen = Tk()
    screen.geometry("378x480")
    screen.title("ENCRYPTION & DECRYPTION")

    def reset():
        code.set("")
        otp_code.set("")
        text1.delete(1.0, END)

    Label(text="Enter text for encryption and decryption", fg="black", font=("Arial", 13)).place(x=10, y=10)
    text1 = Text(font="Arial 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)
    Label(text="Enter secret key for encryption and decryption", fg="black", font=("Arial", 13)).place(x=10, y=170)
    
    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)

    Label(text="Enter 2FA code", fg="black", font=("Arial", 13)).place(x=10, y=240)
    otp_code = StringVar()
    Entry(textvariable=otp_code, width=19, bd=0, font=("arial", 25)).place(x=10, y=270)
    
    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=310)
    Button(text="DECRYPT", height="2", width=23, bg="#00BD56", fg="white", bd=0, command=decrypt).place(x=200, y=310)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=360)
    
    # Display the TOTP setup information
    Button(text="Setup TOTP", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=display_totp_secret).place(x=10, y=410)

    screen.mainloop()

main_screen()
