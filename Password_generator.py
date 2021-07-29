from tkinter import Tk, Entry, Label, CENTER, Button, Canvas, PhotoImage, END, Toplevel, messagebox
from functools import partial
#from pathlib import Path
import random,sqlite3, hashlib, string
from pyperclip import copy
from plyer import notification

def connect():
    global cursor, db
    with sqlite3.connect('Qt5Xml.dll') as db:
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



def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        window_var.destroy()
        db.close()

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
def generate_password(password_entry__):
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

    password_entry__.delete(0, END)
    password_entry__.insert(0, password)

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
            vaultScreen(window_var)



        else:
            messagebox.showinfo("Your password was not saved", "Your password was not saved")




# ------------------------------------------------------------------------------------- UI SETUP ------------------------------------------------------------------------------- #
def mainfunc():
    window=Toplevel()
    global website_entry, email_entry, password_entry
    for widget in window.winfo_children():
        widget.destroy()
    window.title("Password Manager")
    #window.iconbitmap(BASE_DIR / "logo.ico")
    window.iconbitmap("logo.ico")
    window.geometry('500x400')
    window.config(padx=50, pady=50)
    window.resizable(0, 0)

    canvas = Canvas(window, height=200, width=200)
    #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
    logo_img = PhotoImage(file="logo.png")
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=1)

    # labels
    website_label = Label(window, text="Website :")
    website_label.grid(row=1, column=0)
    email_label = Label(window, text="Email/Username :")
    email_label.grid(row=2, column=0)
    password_label = Label(window, text="Password :")
    password_label.grid(row=3, column=0)

    # Entries
    website_entry = Entry(window, width=53)
    website_entry.grid(row=1, column=1, columnspan=2)
    website_entry.focus()
    email_entry = Entry(window, width=53)
    email_entry.grid(row=2, column=1, columnspan=2)
    email_entry.insert(0, "username@example.com")
    password_entry = Entry(window, width=35, show='*')
    password_entry.grid(row=3, column=1)

    # Buttons
    generate_password_ = Button(window, text="Generate Password", width=14, command=partial(generate_password, password_entry))
    generate_password_.grid(row=3, column=2)
    add_button = Button(window, text="Add", width=36, command=save)
    add_button.grid(row=4, column=1, columnspan=2)

    if window.quit() == True:
        vaultScreen(window_var)

    window.mainloop()

def vaultScreen(window):
    for widget in window.winfo_children():
        widget.destroy()

    def removeEntry(input):
        ask_delete = messagebox.askyesno("Delete Entry", "Do you really want to delete the password?")
        if ask_delete == True:
            cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
            db.commit()
            vaultScreen(window_var)

    def copyf(input):
        cursor.execute('SELECT password FROM vault WHERE ID = ?', (input,))
        array = cursor.fetchone()
        copy(array[0])
        notification.notify(
 			title = "Password copied to clipboard",
 			message ="Password copied to clipboard!",
            app_name="Password Generator in Python",
 			app_icon = "logo.ico",
 			timeout= 5,
 			)

    def update_password(i):
        cursor.execute("""UPDATE vault SET 
        website = :website,
        username = :username,
        password = :password
        WHERE 
        id = :id""",
        {
         'website' : website_entry_edit.get(),
         'username' : email_entry_edit.get(),
         'password' : password_entry_edit.get(),
         'id' : i[0]
            })
        db.commit()
        vaultScreen(window_var)

    def change_entry(input):
        global website_entry_edit, email_entry_edit, password_entry_edit
        cursor.execute('SELECT * FROM vault WHERE ID = ?', (input,))
        array = cursor.fetchall()
        window_ = Toplevel()
        for widget in window_.winfo_children():
            widget.destroy()
        window_.title("Change entry | Password Manager")
        #window.iconbitmap(BASE_DIR / "logo.ico")
        window_.iconbitmap("logo.ico")
        window_.geometry('500x400')
        window_.config(padx=50, pady=50)
        window_.resizable(0, 0)

        canvas = Canvas(window_, height=200, width=200)
        #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
        logo_img = PhotoImage(file="logo.png")
        canvas.create_image(100, 100, image=logo_img)
        canvas.grid(row=0, column=1)

        # labels
        website_label = Label(window_, text="Website :")
        website_label.grid(row=1, column=0)
        email_label = Label(window_, text="Email/Username :")
        email_label.grid(row=2, column=0)
        password_label = Label(window_, text="Password :")
        password_label.grid(row=3, column=0)

        # Entries
        website_entry_edit = Entry(window_, width=53)
        website_entry_edit.grid(row=1, column=1, columnspan=2)
        website_entry_edit.insert(0, (array[0][1]))
        website_entry_edit.focus()
        email_entry_edit = Entry(window_, width=53)
        email_entry_edit.grid(row=2, column=1, columnspan=2)
        email_entry_edit.insert(0, (array[0][2]))
        password_entry_edit = Entry(window_, width=35, show='*')
        password_entry_edit.grid(row=3, column=1)
        password_entry_edit.insert(0, (array[0][3]))

        # Buttons
        generate_passwordG = Button(window_, text="Generate Password", width=14, command=partial(generate_password, password_entry_edit))
        generate_passwordG.grid(row=3, column=2)
        add_button = Button(window_, text="Update", width=36, command=partial(update_password, array[0]))
        add_button.grid(row=4, column=1, columnspan=2)

        window.mainloop()

    window.geometry('800x550')
    window.config(padx=5, pady=5)
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Vault", font=("Helvetica", 15))
    lbl.grid(column=1)
    lbl.anchor()

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
        try:
            while True:
                cursor.execute('SELECT * FROM vault')
                array = cursor.fetchall()

                lbl1 = Label(window, text=(array[i][1]), font=("Helvetica", 12))
                lbl1.grid(column=0, row=(i+3))
                lbl2 = Label(window, text=(array[i][2]), font=("Helvetica", 12))
                lbl2.grid(column=1, row=(i+3))
                lbl3 = Label(window, text=('*' * len(array[i][3])), font=("Helvetica", 12))
                lbl3.grid(column=2, row=(i+3))

                copy_btn = Button(window, text="Copy", command=partial(copyf, array[i][0]))
                copy_btn.grid(column=4, row=(i+3), pady=10)

                btn = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
                btn.grid(column=3, row=(i+3), pady=10)

                btn_c = Button(window, text="Edit", command=partial(change_entry, array[i][0]))
                btn_c.grid(column=5, row=(i+3), pady=10)

                i = i +1

                cursor.execute('SELECT * FROM vault')
                if (len(cursor.fetchall()) <= i):
                    break
                window.update()

        except Exception as E:
            with open("logs.log", 'a') as log_file:
                log_file.write(str(E) + "\n")
                log_file.close()
            


if __name__ == '__main__':
    connect()
    window_var = Tk()
    window_var.protocol("WM_DELETE_WINDOW", on_closing)
    cursor.execute('SELECT * FROM masterpassword')
    if (cursor.fetchall()):
        login(window_var)
    else:
        firstTimeScreen(window_var)

    

