import tkinter as tk
from tkinter import *

root=Tk()

# main canvas
canvas = tk.Canvas(root, height=600, width=600, bg="black")
canvas.pack(fill="both", expand=True)

# input box
inputbox=Entry(root, width=40, bg="white", font=("Helvetica", 14), bd=0)
inputbox.pack()
inputbox.insert(0, "Insert password or hash here-")
inputboxwindow = canvas.create_window(300, 200, window=inputbox)

# result box
resultbox = Text(root, width=38, height=3, font=("Helvetica", 20))
resultbox.pack()
resultboxwindow = canvas.create_window(300, 296, window=resultbox)

# buttons
checkbutton = Button(root, text="Grade", font=("Helvetica"), bg="grey")
checkbutton_window = canvas.create_window(317,230, window=checkbutton)

generatebutton = Button(root,text="Generate", font=("Helvetica"), bg="grey")
generatebutton_window = canvas.create_window(250,230, window=generatebutton)

checkhashbutton = Button(root,text="Analyze Hash", font=("Helvetica"), bg="grey")
checkhashbutton_window = canvas.create_window(161,230, window=checkhashbutton)

crackhashbutton = Button(root,text="Crack Hash", font=("Helvetica",), bg="grey")
crackhashbutton_window = canvas.create_window(395,230, window=crackhashbutton)

comparepassbutton = Button(root,text="Vulnerability Check", font=("Helvetica", 12), bg="grey")
comparepassbutton_window = canvas.create_window(516,230, window=comparepassbutton)


timecrackbutton = Button(root,text="Time2Crack", font=("Helvetica", 12), bg="grey")
timecrackbutton_window = canvas.create_window(59,230, window=timecrackbutton)

def input_clear(e):
    if inputbox.get() == "Insert password or hash here-":
        inputbox.delete(0,END)

inputbox.bind("<Button-1>", input_clear)

root.mainloop()