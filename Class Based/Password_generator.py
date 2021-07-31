from tkinter import Frame, Tk, Entry, Label, CENTER, Button, Canvas, PhotoImage, END, Toplevel, messagebox
from functools import partial
#from pathlib import Path
import random,sqlite3, hashlib, string
from pyperclip import copy
from plyer import notification

root = Tk()
root.title("Password Manager by Ishan")
root.iconbitmap("logo.ico")
root.geometry("600x600")

class Main:
    def __init__(self, master):
        frame = Frame(master)
        frame.grid()

        self.button = Button(frame, text = "Ishan", command = self.click).grid(row=0, column=0)

    def click(self):
        messagebox.showinfo(title="Click me even more!!!", message="Click me even more!!!")

Main(root)
root.mainloop()
