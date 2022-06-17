from doctest import OutputChecker
from logging import exception
from re import L
import instaloader
from Sublist3r import sublist3r
import threading
from tkinter import *
from tkinter import font
from tkinter import messagebox
import tkinter
from turtle import color
from dorcker.dorcker import dorcksFunction
from virustotal_domain import domainoutput
from IPwhois import Finaloutput, getipinformation
from tkinterDnD import tk
from Scylla import get_from_scylla
import time
from holehe0.holehe.core import holeheoutput
from ghunt import ghunt as ghun
from FinalRecon.modules.crawler import crawler
from tkinter import ttk
import tkinterDnD
from hash_and_files import get_hash_info
from hash_and_files import generatehash
root = tkinterDnD.Tk()
from Scylla import get_from_scylla
import instaloader
import pyfiglet
import sys
import socket
from datetime import datetime


##################### CONSTANT VARIABLES#####################

guititle="Cyber Recon Application"
Name="Alpha-Crate-Ion"
Rollnumber="Beta"
Section="Gamma"
internalpadding=8
insert_text=""

        #for GUI theme

#button
OptionsFontStyle="InkFree 10"
DefaultButtonColor="darkgrey"
SelectedButtonColor="orange"
ActiveButtonBackgroundColor="white"
SubmitButtonBackColor="blue"
SubmitButtonTextColor="white"

#frame
ServiceFrameBackgroundColor="#3c3c3c"
ServiceFrameBorderColor="#3c3c3c"

MainScreen_FrameColor="#1e1e1e"
MainScreen_FrameBorderColor="black"

SearchbarParentFrameBackColor="#1e1e1e"
Searchbar_FrameColor="#3c3c3c"
Searchbar_FrameBorderColor="black"
ExtraServicesFrameBackgroundColor="#1e1e1e"

OutputFrameBackgroundColor="#030303"
OuputFrameBorderColor="green"

#title
applicationTitlebackgroundColor="#3c3c3c"
TitleFontStyle="Calibri 22 bold"
TitleColor="green"


root.config(background="black")

###############################################################


## GUI Logic

width= root.winfo_screenwidth()
height= root.winfo_screenheight()
root.state('zoomed')
root.title(guititle)

## Application Title
application_title_label=Label(text="Cyber Recon Application", bg=applicationTitlebackgroundColor,
 fg=TitleColor, pady="5", font=TitleFontStyle, borderwidth=5, relief=SUNKEN)
application_title_label.pack(side=TOP, fill=X, padx=20)


##=======================================BACKGROUND FUNCTION DECLARATIONS================================

##variables
domain_IP_url=False
ghunt=False
file_hash=False
scylla=False
sublist=False
emailtophone=False
holehe=True
subserviceselection=False
inputstringisemptyornot=False
selectedsuboption=""

def ShowButton(button_name):
   button_name.pack(padx=5, pady=5, fill=X, side="left")


def HideButton(button_name):
   button_name.pack_forget()

def HideAllButton():
   extraoption_Button1.pack_forget()
   extraoption_Button2.pack_forget()
   extraoption_Button3.pack_forget()
   extraoption_Button4.pack_forget()
   extraoption_Button5.pack_forget()
   extraoption_Button6.pack_forget()
   extraoption_Button7.pack_forget()
   extraoption_Button1.configure(bg=DefaultButtonColor)
   extraoption_Button2.configure(bg=DefaultButtonColor)
   extraoption_Button3.configure(bg=DefaultButtonColor)
   extraoption_Button4.configure(bg=DefaultButtonColor)
   extraoption_Button5.configure(bg=DefaultButtonColor)
   extraoption_Button6.configure(bg=DefaultButtonColor)
   extraoption_Button7.configure(bg=DefaultButtonColor)
   Serviceslabel.pack_forget()
   servicesFrame.pack_forget()
   root.focus()

def get_description(argumen):
    if argumen=="hash":
        a='''Enter the Hash value of malicious file you want to scan
         \nOnce this scan gets completed then you'll get list of Anti-Virus that detected this hash file as malicious file '''
    
    elif argumen=="file":
        a='''Enter the file path or simply drag and drop your file here\n\n
        what happens here is , we'll be retrieving hash value of your file and then that hash value will be passed to 
        Virus Total for scanning 

        Once this scan gets completed then you'll be getting list of of Anti-Virus that detected this hash value as malicious file '''
    elif argumen=="dork":
        a='''Enter the keyword and a number separated by comma for example

                alpha, 10

            so basically what this section do is, it will search 10 dorking link for keyword alpha
        '''
    elif argumen=="insta post downloads":
        a='''!!!!Note: This process is very much Time Consuming since this service downloads all posts!!!!
        
         Enter Victim's instagram username and this service will create a directory of that username and download all posts there 
        
        \t!!!! Note: This Feature will only work if Victim's account is public  !!!!'''
    elif argumen=="port scanner input format":
        a='''Now here you need to enter IP Address then starting port number and then ending port number and all these should be separated by commas
        
        eg: 192.168.1.1, 440, 450
        
        Now here in above's example 
        440 is our starting port number
        450 is our ending port number'''

    elif argumen=="subdomains finder":
        a='''This will give you all possible subdomains related to provided domain
        !!!!Note: This process is very much Time Consuming
        that is because it search on different search engines to get all possible subdomains'''
    return a
loadingwindow = Toplevel(root)
loadingwindow.title("Hold on A process is running")
width=400
height=200
screenwidth=root.winfo_screenwidth()
screenheight=root.winfo_screenheight()
x=(screenwidth / 2) - (width / 2)
y=(screenheight / 2) - (height / 2)
loadingwindow.geometry(f'{width}x{height}+{int(x)}+{int(y)}')
loadingwindow.overrideredirect(True)
loadingwindow.config(background="white")
text=Label(loadingwindow, text="Hold on let the background process \n complete or else code will get stuck", font="Calibri 13 bold")
loadingwindow.columnconfigure(0, weight=1)
text.grid(row=0, column=0, pady=20)
progressbar=ttk.Progressbar(loadingwindow, orient=HORIZONTAL, length=300, mode="determinate")
progressbar.grid(row=1, column=0, pady=20)
progressbar.start(10)
loadingwindow.withdraw()


def LoadingScreen(openorclose):
    if openorclose=="open":
        loadingwindow.deiconify()
    elif openorclose=="close":
        loadingwindow.withdraw()
        
        
        
        




def Option1():
    option1_Button.configure(bg=SelectedButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option4_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Choose any one from below")
    text.delete("1.0","end")
    
    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=False
    subserviceselection=False
    domain_IP_url=True
    ghunt=False
    file_hash=False
    scylla=False
    sublist=False
    emailtophone=False

    HideAllButton()
    ShowButton(Serviceslabel)
    ShowButton(extraoption_Button1)
    extraoption_Button1.configure(text="Domain")
    ShowButton(extraoption_Button2)
    extraoption_Button2.configure(text="IP")
    ShowButton(extraoption_Button3)
    extraoption_Button3.configure(text="Url")
    root.focus()


def Option2():
    option2_Button.configure(bg=SelectedButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option4_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Choose any one from below")
    text.delete("1.0","end")

    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=False
    subserviceselection=False
    domain_IP_url=False
    ghunt=False
    file_hash=True
    scylla=False
    sublist=False
    emailtophone=False

    HideAllButton()
    ShowButton(Serviceslabel)
    ShowButton(extraoption_Button1)
    extraoption_Button1.configure(text="File")
    ShowButton(extraoption_Button2)
    extraoption_Button2.configure(text="Hash")
    root.focus()

def Option3():
    option3_Button.configure(bg=SelectedButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option4_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Enter keyword and no that you want to search as Google Dorking links")
    text.delete("1.0","end")
    text.insert(END, get_description("dork"))

    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=False
    subserviceselection=True
    domain_IP_url=False
    ghunt=False
    file_hash=False
    scylla=False
    sublist=False
    emailtophone=True
    HideAllButton()
    root.focus()



def option_holehe():
    option_holehe_Button.configure(bg=SelectedButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option4_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Enter Email Address: eg. alphabeta@gmail.com")
    text.delete("1.0","end")

    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, insert_text, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=True
    subserviceselection=True
    domain_IP_url=False
    ghunt=False
    file_hash=False
    scylla=False
    sublist=False
    emailtophone=False
    HideAllButton()
    root.focus()


def Option4():
    option4_Button.configure(bg=SelectedButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Choose any service from below")
    text.delete("1.0","end")
    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=False
    subserviceselection=False
    domain_IP_url=False
    ghunt=True
    file_hash=False
    scylla=False
    sublist=False
    emailtophone=False

    HideAllButton()
    ShowButton(Serviceslabel)
    ShowButton(extraoption_Button1)
    extraoption_Button1.configure(text="email")
    ShowButton(extraoption_Button2)
    extraoption_Button2.configure(text="giai")
    ShowButton(extraoption_Button3)
    extraoption_Button3.configure(text="youtube")
    text.delete("1.0","end")
    root.focus()


def Option5():
    option4_Button.configure(bg=DefaultButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=SelectedButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Choose any service from below")
    text.delete("1.0","end")
    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=False
    subserviceselection=False
    domain_IP_url=False
    ghunt=False
    file_hash=False
    scylla=True
    sublist=False
    emailtophone=False
    HideAllButton()
    ShowButton(Serviceslabel)
    ShowButton(extraoption_Button1)
    extraoption_Button1.configure(text="Instagram")
    ShowButton(extraoption_Button2)
    extraoption_Button2.configure(text="Download posts of Insta")
    ShowButton(extraoption_Button3)
    extraoption_Button3.configure(text="username")
    ShowButton(extraoption_Button4)
    extraoption_Button4.configure(text="Port Scanning")
    ShowButton(extraoption_Button5)
    extraoption_Button5.configure(text="IP dump from server")
    ShowButton(extraoption_Button6)
    extraoption_Button6.configure(text="Available webcam")
    ShowButton(extraoption_Button7)
    extraoption_Button7.configure(text="Geolocate IP")
    root.focus()

def Option6():
    option4_Button.configure(bg=DefaultButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=SelectedButtonColor)
    option7_Button.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg=DefaultButtonColor)
    inputstring_Entry.insert(0, "  Enter domain name: eg. amazon.com")
    text.delete("1.0","end")
    text.insert(END, get_description("subdomains finder"))
    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe, inputstringisemptyornot
    inputstringisemptyornot=True
    holehe=False
    subserviceselection=True
    domain_IP_url=False
    ghunt=False
    file_hash=False
    scylla=False
    sublist=True
    emailtophone=False
    HideAllButton()
    root.focus()


def Option7():
    option4_Button.configure(bg=DefaultButtonColor)
    option2_Button.configure(bg=DefaultButtonColor)
    option3_Button.configure(bg=DefaultButtonColor)
    option_holehe_Button.configure(bg=DefaultButtonColor)
    option1_Button.configure(bg=DefaultButtonColor)
    option5_Button.configure(bg=DefaultButtonColor)
    option6_Button.configure(bg=DefaultButtonColor)
    option7_Button.configure(bg=SelectedButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, holehe
    holehe=False
    subserviceselection=False
    domain_IP_url=False
    ghunt=False
    file_hash=False
    scylla=False
    sublist=False
    emailtophone=False
    text.delete("1.0","end")
    printlogo()
    HideAllButton()
    root.focus()


def ExtraOption1():
    global subserviceselection, selectedsuboption
    subserviceselection=True
    extraoption_Button1.configure(bg=SelectedButtonColor)
    extraoption_Button2.configure(bg=DefaultButtonColor)
    extraoption_Button3.configure(bg=DefaultButtonColor)
    extraoption_Button4.configure(bg=DefaultButtonColor)
    extraoption_Button5.configure(bg=DefaultButtonColor)
    extraoption_Button6.configure(bg=DefaultButtonColor)
    extraoption_Button7.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot
    inputstringisemptyornot=True
    if (ghunt):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter email-address: eg. alphabeta@gmail.com")
        inputstringisemptyornot=True
        selectedsuboption="email"
        
    
    elif(domain_IP_url):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, '  Enter Domain name: eg. amazon.com')
        inputstringisemptyornot=True
        selectedsuboption="domain name"
        

    elif(file_hash):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, '  Enter file path: eg. E:/Projects/CyberApplication/testfile.txt  or drag n drop')
        inputstringisemptyornot=True
        selectedsuboption="upload file"
        uploadingfile()

    if (scylla):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter Instagram username: eg. davesmith")
        inputstringisemptyornot=True
        selectedsuboption="insta username"
    
    root.focus()


    
   
def ExtraOption2():
    global subserviceselection
    subserviceselection=True
    extraoption_Button1.configure(bg=DefaultButtonColor)
    extraoption_Button2.configure(bg=SelectedButtonColor)
    extraoption_Button3.configure(bg=DefaultButtonColor)
    extraoption_Button4.configure(bg=DefaultButtonColor)
    extraoption_Button5.configure(bg=DefaultButtonColor)
    extraoption_Button6.configure(bg=DefaultButtonColor)
    extraoption_Button7.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot, selectedsuboption
    if (ghunt==True):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter Gaia Id: eg. 108017910053096080000")
        inputstringisemptyornot=True
        selectedsuboption='gaia'
    elif(domain_IP_url):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter Ip Address: eg. 54.32.45.22")
        inputstringisemptyornot=True
        selectedsuboption='ip'
    elif(file_hash):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, '  Enter Hash Value: eg. e7ae40d25a6da15cdd3712f4f55153ac')
        text.delete("1.0","end")
        text.insert(END, get_description("hash"))
        inputstringisemptyornot=True
        selectedsuboption="hash"
    if (scylla):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter Insta username: eg. davesmitht ")
        inputstringisemptyornot=True
        text.delete("1.0","end")
        text.insert(END, get_description("insta post downloads"))
        selectedsuboption='insta username post'
    root.focus()



def ExtraOption3():
    global subserviceselection
    subserviceselection=True
    extraoption_Button1.configure(bg=DefaultButtonColor)
    extraoption_Button2.configure(bg=DefaultButtonColor)
    extraoption_Button3.configure(bg=SelectedButtonColor)
    extraoption_Button4.configure(bg=DefaultButtonColor)
    extraoption_Button5.configure(bg=DefaultButtonColor)
    extraoption_Button6.configure(bg=DefaultButtonColor)
    extraoption_Button7.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot, selectedsuboption
    if (ghunt):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter Youtube Channel Link: eg. https://www.youtube.com/c/AddictedA1")
        inputstringisemptyornot=True
        selectedsuboption="youtube"
    if (domain_IP_url):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter url: eg. https://amazon.com")
        inputstringisemptyornot=True
        selectedsuboption="url"
    if (scylla):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter username: eg. davesmith")
        inputstringisemptyornot=True
        selectedsuboption='username'
    root.focus()



def ExtraOption4():
    global subserviceselection, selectedsuboption
    subserviceselection=True
    extraoption_Button1.configure(bg=DefaultButtonColor)
    extraoption_Button2.configure(bg=DefaultButtonColor)
    extraoption_Button3.configure(bg=DefaultButtonColor)
    extraoption_Button4.configure(bg=SelectedButtonColor)
    extraoption_Button5.configure(bg=DefaultButtonColor)
    extraoption_Button6.configure(bg=DefaultButtonColor)
    extraoption_Button7.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot
    if (scylla):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter IP address with starting port number and ending port number eg: given below")
        text.delete("1.0","end")
        text.insert(END, get_description("port scanner input format"))
        inputstringisemptyornot=True
        selectedsuboption="port scanning"
    root.focus()


def ExtraOption5():
    global subserviceselection, selectedsuboption
    subserviceselection=True
    extraoption_Button1.configure(bg=DefaultButtonColor)
    extraoption_Button2.configure(bg=DefaultButtonColor)
    extraoption_Button3.configure(bg=DefaultButtonColor)
    extraoption_Button4.configure(bg=DefaultButtonColor)
    extraoption_Button5.configure(bg=SelectedButtonColor)
    extraoption_Button6.configure(bg=DefaultButtonColor)
    extraoption_Button7.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot
    if (scylla):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  Enter servername: eg. apache")
        inputstringisemptyornot=True
        selectedsuboption="server name"
    root.focus()


def ExtraOption6():
    global subserviceselection, selectedsuboption
    subserviceselection=True
    extraoption_Button1.configure(bg=DefaultButtonColor)
    extraoption_Button2.configure(bg=DefaultButtonColor)
    extraoption_Button3.configure(bg=DefaultButtonColor)
    extraoption_Button4.configure(bg=DefaultButtonColor)
    extraoption_Button5.configure(bg=DefaultButtonColor)
    extraoption_Button6.configure(bg=SelectedButtonColor)
    extraoption_Button7.configure(bg=DefaultButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot
    if (scylla):
        inputstring_Entry.configure(fg=DefaultButtonColor)
        inputstring_Entry.insert(0, "  write show here and hit enter eg: show")
        inputstringisemptyornot=True
        selectedsuboption="webcam"
    root.focus()


def ExtraOption7():
    global subserviceselection, selectedsuboption
    subserviceselection=True
    extraoption_Button1.configure(bg=DefaultButtonColor)
    extraoption_Button2.configure(bg=DefaultButtonColor)
    extraoption_Button3.configure(bg=DefaultButtonColor)
    extraoption_Button4.configure(bg=DefaultButtonColor)
    extraoption_Button5.configure(bg=DefaultButtonColor)
    extraoption_Button6.configure(bg=DefaultButtonColor)
    extraoption_Button7.configure(bg=SelectedButtonColor)
    inputstring_Entry.delete(0, 'end')
    text.delete("1.0","end")
    global inputstringisemptyornot
    inputstring_Entry.configure(fg=DefaultButtonColor)
    if (scylla):
        inputstring_Entry.insert(0, "  Enter IP Address: eg. 1.1.1.1")
        inputstringisemptyornot=True
        selectedsuboption="ip"
    root.focus()

def printlogo():
    def callback():
        myinfo = f"""
================================================================================
||******************  Author  :  Tejas Tripathi  ************************************||
||******************  Class   :  alpha/beta/gama  **********************************||
||******************  Roll no :  0987654321  **************************************||
================================================================================ 


"""
        for col in myinfo:
            text.insert(END, col)
            LoadingScreen("close")
            time.sleep(0.0040)
    
    t=threading.Thread(target=callback)
    t.start()

    


def getholeheoutput(emaildata):
    LoadingScreen("open")
    def callback():
        l1=holeheoutput(emaildata)
        global insert_text
        found=[]
        notfound=[]
        ratelimit=[]
        
        for i in l1:
            if "[x]" in i:
                ratelimit.append(i)
                ratelimit.append("\n")
                
            elif "[-]" in i:
                notfound.append(i)
                notfound.append("\n")
                
            elif "[+]" in i:
                found.append(i)
                found.append('\n')
                
            else:
                print("bunchof nothing")
                print("\n")
        
        text.insert(END, "\n This email is found in following sites: \n")
        for i in found:
            text.insert(END, i)
        found.clear()

        text.insert(END, "\n\n\n We've tried the following sites where we didn't found this email: \n")
        for i in notfound:
            text.insert(END, i)
        notfound.clear()

        text.insert(END, "\n\n\n Due to rate limit we cannot find this email: \n")
        for i in ratelimit:
            text.insert(END, i)
        ratelimit.clear()
        l1.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()
    
def ghuntoutput(data):
    global selectedsuboption
    if selectedsuboption=="email":
        ghuntemail(data)
    elif selectedsuboption=="gaia":
        ghuntgaia(data)
    elif selectedsuboption=="youtube":
        ghuntyoutube(data)

def ghuntemail(data):
    LoadingScreen("open")
    def callback():
        l1=ghun.f_calls("email", data)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
            text.insert(END, "\n")
        l1.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()

def ghuntgaia(data):
    LoadingScreen("open")
    def callback():
        l1=ghun.f_calls("gaia", data)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
            text.insert(END, "\n")
        l1.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()

def ghuntyoutube(data):
    LoadingScreen("open")
    def callback():
        l1=ghun.f_calls("youtube", data)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
            text.insert(END, "\n")
        l1.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()

def crawlurl(url):
    LoadingScreen("open")
    def callback():
        FinalOutput=[]
        data={}
        target=url
        output = {'format': "txt",'file': "output",'export': False}
        crawler(target, output, data)
        alpha=data["module-Crawler"]
        for i in alpha:
            print(f"\n\n\n============== {i} ==============\n")
            FinalOutput.append(f"\n\n============== {i} ==============\n")
            if isinstance(alpha[i], list):
                for j in alpha[i]:
                    FinalOutput.append(f"\t{j}\n")
                    print(f"\t{j}\n")
            else:
                print(f"\t{i} ==> {alpha[i]}")
                FinalOutput.append(f"\t{i} ==> {alpha[i]}")
        
        for i in FinalOutput:
            text.insert(END, i)
        FinalOutput.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()

def getdomaininfo(url):
    LoadingScreen("open")
    def callback():
        l1=domainoutput(url)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
        l1.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()

def getipinfo(ip):
    LoadingScreen("open")
    def callback():
        l1=getipinformation(ip)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
        l1.clear()
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()


def domainipurl(data):
    global selectedsuboption
    if selectedsuboption=="domain name":
        urldata=inputstring_Entry.get()
        getdomaininfo(urldata)
    elif selectedsuboption=="ip":
        ipdata=inputstring_Entry.get()
        getipinfo(ipdata)
    elif selectedsuboption=="url":
        urldata=inputstring_Entry.get()
        crawlurl(urldata)


def hash_info(hash):
    LoadingScreen("open")
    def callback():
        try:
            l1=get_hash_info(hash)
            text.insert(END, "\n\n")
            for i in l1:
                text.insert(END, i)
            l1.clear()
        except:
            text.insert(END, "This file not found in virusTotal")
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()

def get_file_hash_output():
    if selectedsuboption=="hash":
        hashvalue=inputstring_Entry.get()
        hash_info(hashvalue)
    elif selectedsuboption=="upload file":
        filename=inputstring_Entry.get()
        hashvalueoffile=generatehash(filename)
        hash_info(str(hashvalueoffile))


stringvar = tkinter.StringVar()
stringvar.set('Drop here or drag from here!')

def drop(event):
    global inputstringisemptyornot
    if file_hash and selectedsuboption=="upload file":
        stringvar.set(event.data)
        text.delete("1.0","end")
        inputstring_Entry.delete(0, 'end')
        inputstring_Entry.insert(0, event.data)
        inputstringisemptyornot=False

def uploadingfile():
    text.register_drop_target("*")
    text.delete("1.0","end")
    text.insert(END, get_description("file"))
    if file_hash and selectedsuboption=="upload file":
        text.bind("<<Drop>>", drop)


def googledorkfunc(query, totalno):
    LoadingScreen("open")
    def callback():
        l1=dorcksFunction(query.strip(), totalno.strip())
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
            text.insert(END, "\n")
        l1.clear()
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()


def printinstauserinfo(username):
    LoadingScreen("open")
    def callback():
        insta_info=[]
        bot = instaloader.Instaloader()
        Username = inputstring_Entry.get()
        bot.download_profile(Username, profile_pic_only = True)
        profile = instaloader.Profile.from_username(bot.context, Username.strip())
        print("Username: ", profile.username)
        insta_info.append(f"Username: {profile.username}\n")
    
        print("User ID: ", profile.userid)
        insta_info.append(f"User ID: {profile.userid}\n")

        print("Number of Posts: ", profile.mediacount)
        insta_info.append(f"Number of Posts: {profile.mediacount}\n")
        
        print("Followers: ", profile.followers)
        insta_info.append(f"Followers: {profile.followers}\n")
        
        print("Followees: ", profile.followees)
        insta_info.append(f"Following: {profile.followees}\n")

        print("Bio: ", profile.biography,profile.external_url)
        insta_info.append(f"Bio: {profile.biography,profile.external_url}\n")

        text.insert(END, "\n\n")
        for i in insta_info:
            text.insert(END, i)
        insta_info=[]
        LoadingScreen("close")
            
    t=threading.Thread(target=callback)
    t.start()
    

def download_insta_post(username):
    LoadingScreen("open")
    text.insert(END, "Now this is a bit long process where this service will download all post of victim's Account\n")
    text.insert(END, "And if you press ctrl + c to break this process then whole UI will gets closed\n")
    text.insert(END, "\t\t!!!Therefore have Patience!!!\n\n")
    text.insert(END, "Starting Account Verification Process")
    def callback():
        text.insert(END, "\n\n")
        try:
            bot = instaloader.Instaloader()
            Username = username
            bot.download_profile(Username, profile_pic_only = True)
            text.insert(END, "Account Verification Process Successfully Completed \n")
            profile = instaloader.Profile.from_username(bot.context, Username)
            text.insert(END, "A Directory had been created just now with name of Victim's username and its profile pic in it\n")
            text.insert(END, "Scanning all the posts\n")
            posts = profile.get_posts()
            text.insert(END, "Scanning Process Completed\n")

            text.insert(END, "Starting Posts Downloading Process\n")
            
            
            for index, post in enumerate(posts, 1):
                try:
                    bot.download_post(post, target=f"{profile.username}")
                except KeyboardInterrupt as ki: 
                    text.insert(END, "breaking Current Processs\n")
                    break
            text.insert(END, "Posts Downloading Process Completed Successfully\n")
        except Exception as e:
            text.insert(END, e)
            text.insert(END, "\n\nMaybe Account not Found or Internet Issue or Something went wrong")
            text.insert(END, "\nOr Download limit exceeds therefore instagram asking for login")
        
        LoadingScreen("close")
    
    t=threading.Thread(target=callback)
    t.start()

def portscanning(ipaddress, starting_port, ending_port):
    LoadingScreen("open")
    def callback():
        start=int(starting_port)
        end=int(ending_port)
        ascii_banner = pyfiglet.figlet_format("PORT SCANNER", font = "starwars")
        print(ascii_banner)
        target=ipaddress

        #linebreaker
        breaker="-"*50

        # Add Banner
        print("-" * 50)

        text.insert(END, f"\n\n {breaker}")
        print("Scanning Target: " + target)
        text.insert(END, f"\nScanning Target: {target}")
        print("Scanning started at:" + str(datetime.now()))
        text.insert(END, f"Scanning started at: {datetime.now()}")
        text.insert(END, f"\n {breaker}")

        try:
            for port in range(start,end):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                
                # returns an error indicator
                result = s.connect_ex((target,port))
                if result ==0:
                    print(f"Port {port} is open")
                    text.insert(END, f"\nPort {port} is open")
                else:
                    print(f"Port {port} is closed")
                    text.insert(END, f"\nPort {port} is closed")
                s.close()
                
        except KeyboardInterrupt:
                print("\n Exiting Program !!!!")
                text.insert(END, "\n Exiting Program !!!!")
                sys.exit()
        except socket.gaierror:
                print("\n Hostname Could Not Be Resolved !!!!")
                text.insert(END, "\n Hostname Could Not Be Resolved !!!!")
                sys.exit()
        except socket.error:
                print("\n Server not responding !!!!")
                text.insert(END, "\n Server not responding !!!!")
                sys.exit()
        LoadingScreen("close")

    t=threading.Thread(target=callback)
    t.start()


def usernamesearch(username):
    LoadingScreen("open")
    def callback():
        l1=get_from_scylla.dump_user_data(username)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
            text.insert(END, "\n")
        l1.clear()
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()


def ipdumpfromserver(servername):
    LoadingScreen("open")
    def callback():
        l1=get_from_scylla.shodan_lookup(servername)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
        l1.clear()
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()

def webcamlist(query):
    LoadingScreen("open")
    def callback():
        l1=get_from_scylla.shodan_webcam("webcamxp")
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
        l1.clear()
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()

def geolocateip(ipaddress):
    LoadingScreen("open")
    def callback():
        l1=get_from_scylla.geo_retrieve_ip_information(ipaddress)
        text.insert(END, "\n\n")
        for i in l1:
            text.insert(END, i)
        l1.clear()
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()


def getscyllaoutput():
    if selectedsuboption=="insta username":
        username=inputstring_Entry.get()
        printinstauserinfo(username)

    elif selectedsuboption=="insta username post":
        username=inputstring_Entry.get()
        download_insta_post(username)
    
    elif selectedsuboption=="username":
        username=inputstring_Entry.get()
        usernamesearch(username)

    elif selectedsuboption=="port scanning":
        gotinput=inputstring_Entry.get()
        inputs_formatting=gotinput.split(",")

        portscanning(inputs_formatting[0].strip(), inputs_formatting[1].strip(), inputs_formatting[2].strip())

    elif selectedsuboption=="server name":
        servername=inputstring_Entry.get()
        ipdumpfromserver(servername)
    
    elif selectedsuboption=="webcam":
        servername=inputstring_Entry.get()
        webcamlist("webcamxp")

    elif selectedsuboption=="ip":
        ipaddress=inputstring_Entry.get()
        geolocateip(ipaddress)
    
        
def getsubdomains(domain):
    LoadingScreen("open")
    def callback():
        l1=sublist3r.interactive(domain)
        if len(l1) == 0:
            text.insert(END, "No subdomain found\n")
        else:
            text.insert(END, "\n\n")
            text.insert(END, f'Total no. of Subdomains found are: {len(l1)}\n')
            for i in l1:
                text.insert(END, f'\t {i}')
                text.insert(END, "\n")
            l1.clear()
        LoadingScreen("close")
    t=threading.Thread(target=callback)
    t.start()


def submitbutton(event):
    global domain_IP_url, ghunt, file_hash, scylla, sublist, emailtophone, subserviceselection, insert_text
    text.delete("1.0","end")
    
    if domain_IP_url or ghunt or file_hash or scylla or sublist or emailtophone or holehe== True:
        if subserviceselection==True:
            if len(inputstring_Entry.get()) == 0:
                messagebox.showwarning("Input is Empty", "Please provide proper data in order to proceed")    
            else:
                if inputstringisemptyornot==True:
                    messagebox.showwarning("Input is Empty", "Please provide proper data in order to proceed")
                else:
                    if holehe==True:
                        emaildata=inputstring_Entry.get()
                        # getholeheoutput("kushbhatia40@gmail.com")
                        getholeheoutput(emaildata)
                        inputstring_Entry.delete(0, 'end')
                        Tk.update(root)
                    
                    elif domain_IP_url==True:
                        print('its Domain_IP_Url turn')
                        print(selectedsuboption)
                        domainipurl("abcd")

                    elif ghunt==True:
                        print("its ghunt's time")
                        rawdata=inputstring_Entry.get()
                        ghuntoutput(rawdata)

                    elif file_hash==True:
                        print("its file_hash time")
                        get_file_hash_output()
                    
                    elif emailtophone==True:
                        print("Now Dorking")
                        a=inputstring_Entry.get()
                        if "," in a:
                            ap=a.split(",")
                            googledorkfunc(ap[0], ap[1])
                            # dorcksFunction(ap[0], ap[1])
                        else:
                            text.insert(END, "\n\n\tEnter the query in proper format")
                    
                    elif scylla==True:
                        print("Scylla time")
                        getscyllaoutput()

                    elif sublist==True:
                        print("sublist time")
                        a=inputstring_Entry.get()
                        getsubdomains(a)
                

        else:
            messagebox.showwarning("Select Service", "You have select any service from below in order to proceed")
    else:
        messagebox.showwarning("Select Service", "Select Any Service from Services Pannel")
    
    inputstring_Entry.configure(fg=DefaultButtonColor)



##=======================================SERVICES BOX SECTION STARTED================================
options_Frame=Frame(root, bg=ServiceFrameBackgroundColor, relief="solid", highlightbackground=ServiceFrameBorderColor, highlightcolor=ServiceFrameBorderColor, highlightthickness=2)
options_Frame.pack(side=LEFT, fill=Y, pady=10, padx=10)

option_label=Label(options_Frame, text="Services", font="Calibri 14 bold underline", padx=8, pady=8, bg="white")
option_label.pack(padx=5, pady=5, fill=X)

option1_Button=Button(options_Frame, text="Domain/IP/Url_crawl",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option1)
option1_Button.pack(padx=5, pady=5, fill=X)

option2_Button=Button(options_Frame, text="File/Hash", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option2)
option2_Button.pack(padx=5, pady=5, fill=X)

option3_Button=Button(options_Frame, text="Google Dork", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option3)
option3_Button.pack(padx=5, pady=5, fill=X)

option_holehe_Button=Button(options_Frame, text="Holehe", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=option_holehe)
option_holehe_Button.pack(padx=5, pady=5, fill=X)

option4_Button=Button(options_Frame, text="G-hunt", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option4)
option4_Button.pack(padx=5, pady=5, fill=X)

option5_Button=Button(options_Frame, text="Scylla", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option5)
option5_Button.pack(padx=5, pady=5, fill=X)

option6_Button=Button(options_Frame, text="Sublist3R", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option6)
option6_Button.pack(padx=5, pady=5, fill=X)

option7_Button=Button(options_Frame, text="About me", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=Option7)
option7_Button.pack(padx=5, pady=5, fill=X)


# ##Themes option
# theme_menu= StringVar()
# theme_menu.set("Select Theme")

# drop= OptionMenu(options_Frame, theme_menu,"default", "dark","terminal","solarized","Rusty")
# drop.pack(padx=5, pady=5, fill=X)
# drop.configure(bg="pink")

# Apply_Button=Button(options_Frame, text="Apply theme", font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=apply_theme)
# Apply_Button.pack(padx=5, pady=5, fill=X)

##=======================================SERVICES BOX SECTION COMPLETED================================





##=======================================SEARCH BOX SECTION STARTED================================
MainScreen_Frame=Frame(root, bg=MainScreen_FrameColor, relief="solid", highlightbackground=MainScreen_FrameBorderColor, highlightcolor=MainScreen_FrameBorderColor, highlightthickness=2)
MainScreen_Frame.pack(side=LEFT, fill=BOTH, pady=10, padx=20, expand=1)
MainScreen_Frame.columnconfigure(0, weight=1)
Parent_Searchbar_Frame=Frame(MainScreen_Frame, bg=SearchbarParentFrameBackColor)
Parent_Searchbar_Frame.grid(row=0, column=0, sticky="WENS", pady=5, padx=5)

Search_label=Label(Parent_Searchbar_Frame, text="Search Bar", font="Calibri 14 bold", padx=8, pady=8, bg=Searchbar_FrameColor, fg="white")
Search_label.grid(row=0, column=0)

Parent_Searchbar_Frame.columnconfigure(1, weight=1)
Searchbar_Frame=Frame(Parent_Searchbar_Frame, bg=Searchbar_FrameColor, relief="solid", highlightbackground=Searchbar_FrameBorderColor, highlightcolor=Searchbar_FrameBorderColor, highlightthickness=2)
Searchbar_Frame.grid(row=0, column=1, sticky="WENS", pady=5, padx=5)

Searchbar_Frame.columnconfigure(0, weight=1)

def click(*args):
    global inputstringisemptyornot
    inputstringisemptyornot=False
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.configure(fg="black")

  
def leave(*args):
    inputstring_Entry.delete(0, 'end')
    inputstring_Entry.insert(0, 'Domain/IP/Email/Hash')
    root.focus()

inputstring_Entry=Entry(Searchbar_Frame, textvariable ="inputstring", font = ('Calibri',14,'normal'), bg=Searchbar_FrameColor, fg="black")
inputstring_Entry.grid(row=0, column=0, sticky="WENS", pady=5, padx=5)
inputstring_Entry.insert(0, "  Select Any of these Services  ")
inputstringisemptyornot=True
inputstring_Entry.bind("<Button-1>", click)


Search_Button=Button(Searchbar_Frame, text="Submit",font="Calibri 12 bold", padx=internalpadding, bg=SubmitButtonBackColor, fg=SubmitButtonTextColor)
Search_Button.grid(row=0, column=1, padx=10, pady=10)
Search_Button.bind("<Button-1>",submitbutton)
root.bind('<Return>',submitbutton)



##=======================================SEARCH BOX SECTION COMPLETED================================






##=======================================EXTRA OPTIONS SECTION STARTED================================
servicesFrame=Frame(MainScreen_Frame, bg=ExtraServicesFrameBackgroundColor)
servicesFrame.grid(row=1, column=0, padx=10, sticky="WENS")

Serviceslabel=Label(servicesFrame, text="Pick any one in order to proceed", font="Calibri 12", padx=8, pady=8, bg=MainScreen_FrameColor, fg="white")
Serviceslabel.pack(side="left")
HideButton(Serviceslabel)

extraoption_Button1=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption1)
extraoption_Button1.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button1)

extraoption_Button2=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption2)
extraoption_Button2.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button2)

extraoption_Button3=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption3)
extraoption_Button3.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button3)

extraoption_Button4=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption4)
extraoption_Button4.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button4)

extraoption_Button5=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption5)
extraoption_Button5.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button5)

extraoption_Button6=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption6)
extraoption_Button6.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button6)

extraoption_Button7=Button(servicesFrame, text="Domain/IP",font=OptionsFontStyle, padx=internalpadding, bg=DefaultButtonColor, command=ExtraOption7)
extraoption_Button7.pack(padx=5, pady=5, fill=X, side="left")
HideButton(extraoption_Button7)

##=======================================EXTRA OPTIONS SECTION COMPLETED================================






##=======================================OUTPUT BOX SECTION STARTED================================


Output_label=Label(MainScreen_Frame, text="Output: ", font="Calibri 14 bold", padx=8, bg=MainScreen_FrameColor , fg="green")
Output_label.grid(row=2, column=0, sticky=NW)


MainScreen_Frame.rowconfigure(3, weight=1)
Output_Frame=Frame(MainScreen_Frame, bg=OutputFrameBackgroundColor, relief="solid", highlightbackground=OuputFrameBorderColor, highlightcolor=OuputFrameBorderColor, highlightthickness=3)
Output_Frame.grid(row=3, column=0, sticky="WENS", pady=5, padx=15)


style=ttk.Style()
style.theme_use('classic')
style.configure("Vertical.TScrollbar", background="green", bordercolor="red", arrowcolor="white")

text = Text(Output_Frame, bg=OutputFrameBackgroundColor, fg="green", padx=10, pady=10, font="Calibri 12")
scroll = ttk.Scrollbar(Output_Frame)
text.configure(yscrollcommand=scroll.set)
text.pack(side=LEFT, fill=BOTH, expand=1)
  
scroll.config(command=text.yview)
scroll.pack(side=RIGHT, fill=Y)
  


##=======================================OUTPUT BOX SECTION COMPLETED================================

root.mainloop()








