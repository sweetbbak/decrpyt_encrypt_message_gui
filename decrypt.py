import customtkinter
import pybase64
from tkinter import *
from cryptography.fernet import Fernet as frt
import pyperclip

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.geometry("550x700")
root.title("Encryptor")

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, expand=True)

def crypto(password, message):
    key = pybase64.b64encode(f"{password:<32}".encode("utf-8"))
    encryptor = frt(key=key)
    message = encryptor.encrypt()

def clear():
    
    my_ent.delete(0, "end")
    my_text.delete(0.0, END)
    
def encrypt():
    #get text in box
    secret = my_text.get(1.0, 'end')
    #clear old text
    my_text.delete(1.0, END)
    #get pass key
    keyz = my_ent.get()
    print(repr(keyz))
    #keyz = pybase64.urlsafe_b64encode(bytes(keyz))
    #Fernet 
    f = frt(keyz)
    token = f.encrypt(secret.encode('utf-8'))
    print('encrytped: {0}'.format(token))
    my_text.insert(END, token)
    print('Token type: ', type(token), token)
    
key = type(bytes)

def keygen():
    global key
    key = frt.generate_key()
    print(repr(key))
    my_key.delete(0, 'end')
    my_key.insert(0, key)
    return key
    
def decrypt():
    secret = my_text.get(1.0, 'end')
    my_text.delete(1.0, END)

    keyz = my_ent.get()

    #output = secret.decode('utf-8')
    f=frt(keyz)
    decoded = f.decrypt(secret)
    print('decrytped: {0}'.format(decoded))
    my_text.insert(END, decoded)

def copy():
    copy_text = my_text.get(1.0,END)
    pyperclip.copy(copy_text)

def paste():
    my_text.insert(END, pyperclip.paste())

##---buttons---------------------------------------------------------------

button = customtkinter.CTkButton(master=frame, text="Encrypt", command=encrypt)
button.grid(row=0, column=0, pady=10)

dec_button = customtkinter.CTkButton(master=frame, text="Decrypt", command=decrypt)
dec_button.grid(row=1, column=0, padx=20)

clr_button = customtkinter.CTkButton(master=frame, text="Clear", command=clear)
clr_button.grid(row=0, column=1)

keygen_button = customtkinter.CTkButton(master=frame, text="Generate Key", command=keygen)
keygen_button.grid(row=1, column=1)

cp_button = customtkinter.CTkButton(master=frame, text="Copy", command=copy)
cp_button.grid(row=0, column=2, padx=20)

paste_button = customtkinter.CTkButton(master=frame, text="Paste", command=paste)
paste_button.grid(row=1, column=2, pady=10)

##---labels---------------------------------------------------------------

enc_label = customtkinter.CTkLabel(master=root, text="Encrypt/Decrypt Text...", text_font=("sans-serif", 14))
enc_label.pack()

my_text = Text(master=root, width=50, height=20, )
my_text.pack(pady=10)

dec_label = customtkinter.CTkLabel(master=root, text="Enter the decryption key you want to use to encode/decode...", text_font=("sans-serif", 10))
dec_label.pack()

my_ent = customtkinter.CTkEntry(master=root, text_font=("sans-serif", 14), width=350)
my_ent.pack(pady=10)

key_label = customtkinter.CTkLabel(master=root, text="Generate a new key", text_font=("sans-serif", 10))
key_label.pack()

my_key = customtkinter.CTkEntry(master=root, text_font=("sans-serif", 10), width=350)
my_key.pack(pady=1)

root.mainloop()
