print("Starting the System")
#---------------------------------------------------------------------------------------------------#
import random
import time
from tqdm import tqdm

#value-here-----------------------------------------------------------------------------------------# 
stop = 0
loadtime = random.randint(1,2)
UserInput = 0
user = ""
existedUser =[]
existPW = []
Psw = ""
EU = ""
UserPass = 0
loginuser = ""
currentuser = ""
currentuserPW = ""
usercount = 0
#---------------------------------------------------------------------------------------------------#


#User-file------------------------------------------------------------------------------------------#
with open("userpw.txt", 'r') as f:
        existPW = [line.rstrip('\n') for line in f]
with open("existedUser.txt", 'r') as f:
        existedUser= [line.rstrip('\n') for line in f]
#---------------------------------------------------------------------------------------------------#

def MakeA():
    print("What Username do you want?")
    print("username:")
    user = input()
    EU = existedUser.count(user)
    if EU > 0:
        print("User Exist")
    else:
        with open("existedUser.txt", 'a') as f:
            f.write('\n'+str(user))

def MakePW():
    print("What Password do you want?")
    print("Password:")
    Psw = input()
    EU = existedUser.count(Psw)
    with open("existedUser.txt", 'a') as f:
        f.write('\n'+str(Psw))



def PassCodeC():
    while UserPass == 1:
        print("password:")
        Psw = input()
        currentuserPW = existPW[usercount]
        if Psw == currentuserPW:
            print("login success")
            currentuser = user
        else:
            print("Wrone password")
        
        


def Login():
    print("username:")
    user = input()
    EU = existedUser.count(user)

    if EU > 0:
        currentuser = user
            
    else:
        print("No such user")
        user = ""
def mainsys():

    while stop < 2:

        UserInput = input()
        if UserInput == "L":
            print("S for Support email")
            print("MA for Make an Account")
            print("Login to Login")
            print("STOP to Stop")
        elif UserInput == "S":
            print("xzhaizhai1111@gmail.com")
        elif UserInput == "MA":
            MakeA
            print("Done! Go to Login")
        elif UserInput == "Login":
            Login()
        elif UserInput == "STOP":
            stop = 3
        else:
            print("Sorry no such command, L for Command List")

def checkstop():
    if stop == 3:
        print("you sure to stop?")
        print("Y/N")
        stoppysys()
def stoppysys():
    
    UserInput = input
    if UserInput == "Y":
        print("bye")
    else:
        mainsys()
        checkstop()
#main-system-loading--------------------------------------------------------------------------------#
for i in tqdm (range (100), 
               desc="Loading…", 
               ascii=False, ncols=150):
                if loadtime == 1:
                        time.sleep(0.01)
                elif loadtime ==2:
                        time.sleep(0.02)
                else:
                        print("Sorry, Error")                        
#welcome--------------------------------------------------------------------------------------------#      
print("Complete.")
print("Hi welcome to the PySys(a random name I give to this)")
print("Type L to see command list")

#SYS------------------------------------------------------------------------------------------------#
mainsys()


    

    

