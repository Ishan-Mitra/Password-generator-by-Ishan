from tkinter import Tk, Text
from functools import partial
import os, subprocess

ip = '192.168.1.1'



root = Tk()
tfield = Text(root)
tfield.pack()
def get_info(arg, *args):
    try:
        f = subprocess.call(arg, stdout=subprocess.PIPE)
    except:
        f = "error"
    print(tfield.get("1.0", "current lineend"))
    if f != "error":
        for line in f:
            line = line.strip()
            if line:
                tfield.insert("end", ">>>" + line+"\n")
    else:
        tfield.insert("end", ">>>" + "error"+"\n")
        # tfield.get("current linestart", "current lineend")
tfield.bind("<Return>", partial(get_info, "cls", "cls"))

root.mainloop()