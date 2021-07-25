from tkinter import Tk, Entry, Label, CENTER, Button, Canvas, PhotoImage, END
from tkinter import messagebox
from functools import partial
#from pathlib import Path
import random,sqlite3, hashlib, string, sqlite3
from os import path
from pyperclip import copy
from plyer import notification

#BASE_DIR = Path(__file__).resolve().parent

def connect():
    global cursor, db
    with sqlite3.connect('password_vault.db') as db:
        cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS masterpassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL);
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL);
    """)

def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1

def firstTimeScreen(window):
    window.title("Password Manager")
    window.iconbitmap("logo.ico")
    window.config(padx=50, pady=50)
    window.resizable(0, 0)
    canvas = Canvas(height=200, width=200)
    #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
    logo_img = PhotoImage(file="./logo.png")
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=0)

    lbl = Label(window, text="Choose a Master Password", font=("Helvetica", 18))
    lbl.grid(row=0, column=1)

    txt = Entry(window, width=20, show="*", font=("Helvetica", 15))
    txt.grid(row=1, column=1)
    txt.focus()

    lbl1 = Label(window, text="Re-enter password", font=("Helvetica", 15))
    lbl1.grid(row=2, column=1)

    txt1 = Entry(window, width=20, show="*", font=("Helvetica", 15))
    txt1.grid(row=3, column=1)

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            login(window_var)
        else:
            lbl.config(text="Passwords dont match")

    btn = Button(window, text="Save", command=savePassword, font=("Helvetica", 15))
    btn.grid(row=5, column=1)

    window.mainloop()





def login(window):
    window.title("Password Manager")
    window.iconbitmap("logo.ico")
    window.config(padx=50, pady=50)
    window.resizable(0, 0)

    for widget in window.winfo_children():
        widget.destroy()

    canvas = Canvas(height=200, width=200)
    #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
    logo_img = PhotoImage(file="logo.png")
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=1)

    lbl = Label(window, text="Enter Master Password", font=("Helvetica", 15))
    lbl.config(anchor=CENTER)
    lbl.grid(row=0, column=2)

    txt = Entry(window, width=20, show="*", font=("Helvetica", 15))
    txt.grid(row=1, column=2)
    txt.focus()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen(window_var)
        else:
            txt.delete(0, 'end')
            messagebox.showerror(title="Wrong Password",message="You have entered a wrong password")

    btn = Button(window, text="Submit", command=checkPassword, font=("Helvetica", 15))
    btn.grid(row=1, column=3)

    window.mainloop()





# --------------------------------------------------------------------------- PASSWORD GENERATOR --------------------------------------------------------------- #
def generate_password():
    letters = string.ascii_letters
    numbers = string.digits
    symbols = string.punctuation

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_letters = [random.choice(letters) for _ in range(nr_letters)]
    password_symbols = [random.choice(symbols) for _ in range(nr_symbols)]
    password_numbers = [random.choice(numbers) for _ in range(nr_numbers)]

    password_list = password_letters + password_numbers + password_symbols
    random.shuffle(password_list)

    password = "".join(password_list)

    password_entry.delete(0, END)
    password_entry.insert(0, password)

    copy(password)
    notification.notify(
 			title = "Password copied to clipboard",
 			message ="The generated password has been copied to clipboard. Now you change the password to the generated password and stay secure.",
            app_name="Password Generator in Python",
 			app_icon = "logo.ico",
 			timeout= 5,
 			)





# --------------------------------------------------------------------------------- SAVE PASSWORD ---------------------------------------------------------------------------- #

def save():

    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(title="Oops", message="Please make sure that each and every field is filled up")
        
    else:
        is_ok = messagebox.askyesno(title=website, message=f"These are the details entered : \nEmail: {email} \nPassword: {password} \nAre you sure you want to save this? " )
        if is_ok == True:
            insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
            cursor.execute(insert_fields, (website, email, password))
            db.commit()
            messagebox.showinfo("Password saved sucessfully", "Password saved sucessfully")
            vaultScreen(window_var)



        else:
            messagebox.showinfo("Your password was not saved", "Your password was not saved")




# ------------------------------------------------------------------------------------- UI SETUP ------------------------------------------------------------------------------- #
def mainfunc():
    window=window_var
    global website_entry, email_entry, password_entry, generate_password_
    for widget in window.winfo_children():
        widget.destroy()
    window.title("Password Manager")
    #window.iconbitmap(BASE_DIR / "logo.ico")
    window.iconbitmap("logo.ico")
    window.geometry('500x400')
    window.config(padx=50, pady=50)
    window.resizable(0, 0)

    canvas = Canvas(height=200, width=200)
    #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
    logo_img = PhotoImage(file="logo.png")
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=1)

    # labels
    website_label = Label(text="Website :")
    website_label.grid(row=1, column=0)
    email_label = Label(text="Email/Username :")
    email_label.grid(row=2, column=0)
    password_label = Label(text="Password :")
    password_label.grid(row=3, column=0)

    # Entries
    website_entry = Entry(width=53)
    website_entry.grid(row=1, column=1, columnspan=2)
    website_entry.focus()
    email_entry = Entry(width=53)
    email_entry.grid(row=2, column=1, columnspan=2)
    email_entry.insert(0, "ishanmitra020@gmail.com")
    password_entry = Entry(width=35, show='*')
    password_entry.grid(row=3, column=1)

    # Buttons
    generate_password_ = Button(text="Generate Password", width=14, command=generate_password)
    generate_password_.grid(row=3, column=2)
    add_button = Button(text="Add", width=36, command=save)
    add_button.grid(row=4, column=1, columnspan=2)

    if window.quit() == True:
        vaultScreen(window_var)

    window.mainloop()

def vaultScreen(window):
    for widget in window.winfo_children():
        widget.destroy()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen(window_var)

    def copyf(input):
        cursor.execute('SELECT password FROM vault WHERE ID = ?', (input,))
        array = cursor.fetchone()
        copy(array[0])

    window.geometry('750x550')
    window.config(padx=10, pady=20)
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Vault", font=("Helvetica", 15))
    lbl.grid(column=1)

    btn = Button(window, text="+", command=mainfunc)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            lbl1 = Label(window, text=(array[i][1]), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i+3))
            lbl2 = Label(window, text=(array[i][2]), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i+3))
            lbl3 = Label(window, text=(array[i][3]), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i+3))

            copy_btn = Button(window, text="Copy", command=partial(copyf, array[i][0]))
            copy_btn.grid(column=4, row=(i+3), pady=10)

            btn = Button(window, text="Delete", command=  partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=(i+3), pady=10)

            i = i +1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break


if __name__ == '__main__':
    connect()
    window_var = Tk()
    cursor.execute('SELECT * FROM masterpassword')
    if (cursor.fetchall()):
        login(window_var)
    else:
        firstTimeScreen(window_var)

