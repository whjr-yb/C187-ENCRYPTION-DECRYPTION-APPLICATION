# C186 Project - ENCRYPTION
from tkinter import *
from cryptography.fernet import Fernet
from tkinter import filedialog, messagebox
import os

root = Tk()
root.geometry("500x500")

global_file_name, global_encryption_text = None, None
file = open("key.txt", "r")
key = file.read()
fernet = Fernet(key)
def saveData(file_name, text):
    file = open(f"{file_name}.txt", "w")
    encryptedText = fernet.encrypt(text.encode())
    file.write(encryptedText.decode())

    print(fernet.decrypt(encryptedText).decode())
    messagebox.showinfo("Success", f"{file_name} file has been created successfully.")
def viewData():
    global decryption_text_data
    text_file = filedialog.askopenfilename(title="Open File")
    name = os.path.basename(text_file)
    with open(name, 'rb') as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    print(decrypted.decode())
    decryption_text_data.insert(END, decrypted.decode())


def startDecryption():
    global file_name_entry
    global decryption_text_data
    root.destroy()
 
    decryption_window = Tk()
    decryption_window.geometry("600x500")
    
    decryption_text_data = Text(decryption_window, height=10, width=40, font = 'arial 16', fg="#5050F5")
    decryption_text_data.place(relx=0.5,rely=0.35, anchor=CENTER)
    
    btn_open_file = Button(decryption_window, text="Choose File", font = 'arial 16', command=viewData, relief=FLAT, fg="#5050F5", bg="white")
    btn_open_file.place(relx=0.5,rely=0.8, anchor=CENTER)
    
    decryption_window.configure(bg="#5050F5")
    decryption_window.mainloop()

    
def startEncryption():
    global file_name_entry
    global encryption_text_data
    root.destroy()
 
    encryption_window = Tk()
    encryption_window.geometry("600x500")
    
    file_name_label = Label(encryption_window, text="File Name: " , font = 'arial 18', bg="#5050F5", fg="white")
    file_name_label.place(relx=0.15,rely=0.15, anchor=CENTER)
    
    file_name_entry = Entry(encryption_window, font = 'arial 18', relief=FLAT, fg="#5050F5", bg="white")
    file_name_entry.place(relx=0.5,rely=0.15, anchor=CENTER)
    
    encryption_text_data = Text(encryption_window, height=11, width=40, relief=FLAT, fg="#5050F5", bg="white", font = 'arial 18',)
    encryption_text_data.place(relx=0.5,rely=0.55, anchor=CENTER)
    
    btn_create = Button(encryption_window, text="Create", font = 'arial 16', relief=FLAT, fg="#5050F5", bg="white", command=lambda: saveData(file_name_entry.get(), encryption_text_data.get("1.0", END)))
    btn_create.place(relx=0.9,rely=0.15, anchor=CENTER)
    
    encryption_window.configure(bg="#5050F5")
    encryption_window.mainloop()
    
    
heading_label = Label(root, text="Encryption & Decryption" , font = 'arial 32', bg="#5050F5", fg="white")
heading_label.place(relx=0.5,rely=0.2, anchor=CENTER)

btn_start_encryption = Button(root, text="Start Encryption" , font = 'arial 18' , command=startEncryption, fg="#5050F5", bg="white", relief=FLAT)
btn_start_encryption.place(relx=0.3,rely=0.6, anchor=CENTER)

btn_start_decryption = Button(root, text="Start Decryption" , font = 'arial 18' ,  command=startDecryption, fg="#5050F5", bg="white", relief=FLAT)
btn_start_decryption.place(relx=0.7,rely=0.6, anchor=CENTER)

root.configure(bg="#5050F5")
root.mainloop()

