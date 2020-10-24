
#    15-112: Principles of Programming and Computer Science
#    HW07 Programming: Implementing a Chat Client
#    Name      : Selmane Tabet
#    AndrewID  : stabet
#
#    File Created: October 19th, 2017.
#    Version 1.0, Oct. 24th, 2017.
#
#    Changelog:
#    [CODE]
#     - Initial version.
#
#    Modification History:
#    Start             End
#    10/19  8:00PM     10/20 4:30AM
#    10/20  11:00AM    10/20 12:30PM
#    10/21  4:45AM     10/21 5:50AM
#    10/21  5:00PM     10/22 3:30AM
#    10/22  9:00AM     10/22 12:00PM
#    10/22  5:00PM     10/22 11:00PM
#    10/23  2:00AM     10/23 4:45AM
#    10/23  4:00PM     10/23 11:00PM
#    10/24  12:45AM    10/24 5:30AM
#    10/24  4:00PM     10/24 10:00PM

import socket
import os

########## USE THIS SPACE TO WRITE YOUR HELPER FUNCTIONS ##########

def md5(pwd,CHALLENGE): #This is the MD5 function, it takes a password and a challenge string and returns a message digest to be used for authentication.
    message=pwd+CHALLENGE #Message (combine password with challenge string)
    messmod=message+"1" #Modified (by adding the "1" character) for use in messagedigest
    messagelen=len(message) #Message length, exclude the appended 1.
    lofl=len(str(messagelen)) #Length of message length number
    repeater=512-len(messmod)-lofl #Determine the number of 0s by removing the message (modified) length, as well as the length of the number that represents the length of the message.
    block=messmod+repeater*"0"+str(messagelen)
    M=[]
    for i in range(0,len(block),32):
        total=0
        for j in range(i,i+32):
            total+=ord(block[j])
        M.append(total)
        
    shift=[7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20, 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
    K=[0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]
    a0=int(0x67452301)
    b0=int(0xefcdab89)
    c0=int(0x98badcfe)
    d0=int(0x10325476)
    A=a0
    B=b0
    C=c0
    D=d0
    
    for i in range(64): #Performing bitwise operations, part of the MD5 algorithm.
        if i>=0 and i<=15:
            F=(B & C) | ((~B) & D)
            F=F & 0xFFFFFFFF
            g=i
        elif i>=16 and i<=31:
            F=(D & B) | ((~D) & C)
            F=F & 0xFFFFFFFF
            g=(5*i+1)% (16)
        elif i>=32 and i<=47:
            F=B ^ C ^ D
            F=F & 0xFFFFFFFF
            g=(3*i+5)% (16)
        elif i>=48 and i<=63:
            F=C ^ (B | (~D))
            F=F & 0xFFFFFFFF
            g=(7*i)% (16)
        
        dTemp=D
        D=C
        C=B
        B=B+leftrotate((A+F+K[i]+M[g]),shift[i])
        B=B & 0xFFFFFFFF
        A=dTemp
        
    a0=(a0+A) & 0xFFFFFFFF
    b0=(b0+B) & 0xFFFFFFFF
    c0=(c0+C) & 0xFFFFFFFF
    d0=(d0+D) & 0xFFFFFFFF
    
    messagedigest=str(a0)+str(b0)+str(c0)+str(d0)
    
    return messagedigest
        

def leftrotate(x,c):
    return (x << c) & 0xFFFFFFFF | (x >> (32-c) & 0x7FFFFFFF >> (32-c))


########## FILL IN THE FUNCTIONS TO IMPLEMENT THE CLIENT ##########

def StartConnection (IPAddress, PortNumber): #This function initializes a connection with a server of given IP and listening port and returns a socket object for the client's use.
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IPAddress,PortNumber))
    return s

def login (s, username, password): #Takes username and password, performs MD5 and sends a string with a message digest, then awaits the server's response.
    s.send("LOGIN "+username+"\n")
    cha=s.recv(4096)
    challenge=cha[len("LOGIN  "+username):] #Slice out the challenge string.
    challenge=challenge.strip('\n') #Strip out all special characters.
    challenge=challenge.strip('\t')
    challenge=challenge.strip('\r')
    response=md5(password,challenge) #MD5 function
    s.send("LOGIN "+username+" "+response+"\n") #Send back a string that contains the message digest.
    check=s.recv(4096) #Receive server's response
    if "Success" in check:
        return True
    else:
        return False

def getUsers(s): #This function retrieves a list of all users within the chat network.
    s.send("@users")
    l=s.recv(4096)
    result=[]
    i=0
    ele="" #To accumulate all strings with usernames.
    while i<len(l): #Keep scanning till the end of the received string.
        if l[i]=="@" and ele!="": #If an @ is found and we came across a username already, get rid of the string accumulated so far and append its content into result.
            result.append(ele)
            ele="" #Set the ele string back to empty.
            i+=1
        elif l[i]=="@": #Otherwise, if an @ was found and we did NOT come across a username already, move on because in the next iteration, ele will be filled.
            i+=1
        else:
            ele=ele+l[i] #Add current character to ele and move on.
            i+=1
    if ele!="": #If we just accumulated some string and did not get to append it and empty it, it should be the last username received. Since it is the last substring, it could have special characeters.
        ele=ele.strip("\n") #Strip out any residual special characters.
        ele=ele.strip("\r")
        ele=ele.strip("\t")
        result.append(ele) #Append it into the result list.
    
    if result[2]=="0": #Return empty list if n was 0, meaning that no user found.
        return []
    else:
        return result[3:] #Return a list without size, "users" and n of all users.

def getFriends(s): #This function retrieves a list of all users who are friends within the chat network. Similar algorithm to that of getUsers'.
    s.send("@friends")
    r=s.recv(4096)
    result=[]
    i=0
    ele="" #Same accumulator method used in getUsers. Refer to it for details.
    while i<len(r):
        if r[i]=="@" and ele!="":
            result.append(ele)
            ele=""
            i+=1
        elif r[i]=="@":
            i+=1
        else:
            ele=ele+r[i]
            i+=1
    if ele!="":
        ele=ele.strip("\n")
        ele=ele.strip("\r")
        ele=ele.strip("\t")
        result.append(ele)
    
    if result[2]=="0":
        return [] #Return empty list if n was 0, meaning that no friends were found.
    else:
        return set(result[3:]) #Returns all friends, without duplicates (for the case of repeated adds.).

def sendFriendRequest(s, friend): #This function sends out a friend request to a target username.
    temp=len("@xxxxx@request@friend@"+friend) #Measure the length of the string. size field included as @xxxxx
    zeros=5-len(str(temp)) #Calculate how many zeros are needed to fill the 5 digits.
    s.send("@"+(zeros*"0")+str(temp)+"@request@friend@"+friend) #"0" is being multiplied by the number of copies required to fill the 5 digits, then added into the string to be sent.
    rep=s.recv(4096)
    if "@ok" in rep:
        return True
    else:
        return False

def acceptFriendRequest(s, friend): #This function sends back a friend request acceptance response to the server. Similar algorithm to the sendFriendRequest.
    temp=len("@xxxxx@accept@friend@"+friend) #Same zero filling approach used in sendFriendRequest functions.
    zeros=5-len(str(temp))
    s.send("@"+(zeros*"0")+str(temp)+"@accept@friend@"+friend)
    rep=s.recv(4096)
    if "@ok" in rep:
        return True
    else:
        return False

def sendMessage(s, friend, message): #This function sends a message to a target username, and should be a friend for it to fully work. Similar algorithm to sendFriendRequest and acceptFriendRequest functions.
    temp=len("@xxxxx@sendmsg@"+friend+"@"+message)
    zeros=5-len(str(temp))
    s.send("@"+(zeros*"0")+str(temp)+"@sendmsg@"+friend+"@"+message)
    rep=s.recv(4096)
    if "@ok" in rep:
        return True
    else:
        return False

def sendFile(s, friend, filename): #This function sends a file to a target user.
    f=open(filename)
    con=f.read() #Read the entire file content.
    temp=len("@xxxxx@sendfile@"+friend+"@"+filename+"@"+con) #Same zero filling method used in other functions.
    zeros=5-len(str(temp))
    s.send("@"+(zeros*"0")+str(temp)+"@sendfile@"+friend+"@"+filename+"@"+con) #Send out a string including the full content of the file.
    rep=s.recv(4096)
    if "@ok" in rep:
        return True
    else:
        return False

def getRequests(s): #This function retrieves a list of all pending friend requests.
    s.send("@rxrqst")
    q=s.recv(4096)
    result=[]
    i=0
    ele=""
    while i<len(q): #Same accumulator method used in getUsers. Refer to it for details.
        if q[i]=="@" and ele!="":
            result.append(ele)
            ele=""
            i+=1
        elif q[i]=="@":
            i+=1
        else:
            ele=ele+q[i]
            i+=1
    if ele!="":
        ele=ele.strip("\n")
        ele=ele.strip("\r")
        ele=ele.strip("\t")
        result.append(ele)
    if result[1]=="0":
        return [] #Return empty list if n was 0, meaning that no request was found.
    else:  
        return set(result[2:]) #Returns all requests, without duplicates (for the case of repeated adds.).

def getMail(s): #This function retrieves all unread mails. Both text and files. Files are autodownloaded upon accessing the inbox.
    s.send("@rxmsg")
    r=s.recv(4096)
    messages=[] #List to store strings in the form of ["user1@message1","user2@message2",....]
    files=[] #List to store strings in the form of ["user1@filename1@filecontent1","user2@filename2@filecontent2",....]
    i=0
    while i<len(r)-4: #len(r)-4 to allow for "@msg@" being at the end of a string, which is very unlikely the case.
        ele=""
        if r[i:i+4]=="@msg": #If @msg was detected, let i jump 5 steps forward, skipping the next @ too and start the next scan from the first character of the username.
            i=i+5
            atcount=0
            while atcount<2 and i<len(r)-1: #Stops when a second @ was scanned, meaning that the message has ended and the index was at the @ before the next username.
                if r[i]=="@":
                    atcount+=1
                ele=ele+r[i] #Keep accumulating all characters following the the username, 2 @s are collected, one after the username, and one at the last iteration after the message.
                i+=1
            ele=ele.strip("@") #Strip out the collected @ and all other special characters.
            ele=ele.strip("\r")
            ele=ele.strip("\n")
            ele=ele.strip("\t")
            messages.append(ele) #Append that string, which now is in the form of "userN@messageN" into messages list.
            i-=1
        else:
            i+=1 #Skip through, nothing to look at.
    i=0
    while i<len(r)-5: #Similar while loop and structure to the above messages loop.
        ele=""
        if r[i:i+5]=="@file":
            i=i+6
            atcount=0
            while atcount<3 and i<len(r)-1:
                if r[i]=="@":
                    atcount+=1
                ele=ele+r[i]
                i+=1
            ele=ele.strip("@")
            ele=ele.strip("\r")
            ele=ele.strip("\n")
            ele=ele.strip("\t")
            files.append(ele) #Append that string, which now is in the form of "userN@filenameN@filecontentN" into files list.
            i-=1
        else:
            i+=1
    allmessages=[] #Initialized to store tuples of usernames and messages.
    allfiles=[] #Initialized to store tuples of usernames and filenames.
    p=os.getcwd() #Retrieve the directory path of this code, to save any incoming files into the same directory.
    for i in range(len(messages)):
        temp=messages[i].split("@") #Split the "userN@messageN" into a list of two elements and append them as a tuple into allmessages.
        allmessages.append((temp[0],temp[1]))
    for j in range(len(files)):
        temp=files[j].split("@") #Split the "userN@filenameN@filecontentN" into a list of three elements.
        name=os.path.join(p,temp[1]) #Name of the file is now in the form of full directory+filename, where filename is the second element of the split list. Filename has an extension included as well.
        f=open(name,"w") #Open the file for writing.
        f.write(temp[2]) #Put in the file content, which is represented by the third element of the split list. 
        f.close() #Close file to save changes.
        allfiles.append((temp[0],temp[1])) #Append a tuple of the username and filename into allfiles.
    if r[7]=="0": #Index 7 is where n is always located; "@XXXXX@n". Return empty if no new messages or files were found.
        return ([],[])
    else:
        return (allmessages,allfiles) #Return a tuple of a pair of lists with tuples inside them.

########## CLIENT PROGRAM HELPER FUNCTIONS: CHANGE ONLY IF NEEDED ##########

def PrintUsage(s):
    print ">> Menu:"
    print "     Menu            Shows a Menu of acceptable commands"
    print "     Users           List all active users"
    print "     Friends         Show your current friends"
    print "     Add Friend      Send another friend a friend request"
    print "     Accept Friend   Accept a friend request"
    print "     Send Message    Send a message to a friend"
    print "     Send File       Send a file to a friend"
    print "     Requests        See your friend requests"
    print "     Messages        See the new messages you recieved"
    print "     Score           Print your current score"
    print "     Exit            Exits the chat client"
    
def ShowUsers(s):
    Users = getUsers(s)
    if Users == []:
        print ">> There are currently no active users"
    else:
        print ">> Active users:"
        for u in Users:
            print "     " + u
    
def ShowFriends(s):
    Friends = getFriends(s)
    if Friends == []:
        print ">> You currently have no friends"
    else:
        print ">> Your friends:"
        for f in Friends:
            print "     " + f
    
def AddFriend(s):
    friend = raw_input("Please insert the username of the user you would like to add as a friend: ")
    if sendFriendRequest(s, friend): print friend, "added succesfully"
    else: "Error adding " + friend + ". Please try again."
    
def AcceptFriend(s):
    friend = raw_input("Please insert the username of the user you would like to accept as a friend: ")
    if acceptFriendRequest(s, friend): print "Request from " + friend + " accepted succesfully"
    else: "Error accepting request from " + friend + ". Please try again." 
    
def SendMessage(s):
    friend = raw_input("Please insert the username of the friend you would like to message: ")
    message = raw_input("Please insert the message that you would like to send: ")
    if friend in getFriends(s):
        if sendMessage(s, friend, message): print "Mesage sent to " + friend + " succesfully"
        else: "Error sending message to " + friend + ". Please try again."
    else: print friend, "is not a Friend. You must add them as a friend before you can message them."

def SendFile(s):
    friend = raw_input("Please insert the username of the friend you would like to mail a file: ")
    filename = raw_input("Please insert the name of the file you'd like to send: ")
    if friend in getFriends(s):
        if sendFile(s, friend, filename): print "File sent to " + friend + " succesfully"
        else: "Error sending file to " + friend + ". Please try again."
    else: print friend, "is not a Friend. You must add them as a friend before you can send them a file."

    
def ShowRequests(s):
    Requests = getRequests(s)
    if Requests == []:
        print ">> You currently have no friend requests"
    else:
        print ">> The following users have asked to be your friends:"
        for r in Requests:
            print "     " + r
    
def ShowMessages(s):
    (Messages, Files) = getMail(s)
    if Messages == []:
        print ">> You have no new messages"
    else:
        print ">> You have recieved the following messages:"
        for (u, m) in Messages:
            print "     " + u + " says: " + m
    if Files == []:
        print ">> You have no new files"
    else:
       print ">> You also recieved the following Users:"
       for (u, f) in Files:
            print "File " + f +" recieved from: " + u + " and downloaded successfully."

def ShowScore(s):
    s.send("@getscore\n")
    data = s.recv(4096)
    score = data.split('@')
    print "Your Score:", score[2]
    print "task 1", score[3]
    print "task 2", score[4]
    print "task 3", score[5]
    print "task 4", score[6]
    print "task 5", score[7]
    print "task 6", score[8]
    

##########  MAIN CODE, CHANGE ONLY IF ABSOLUTELY NECCESSARY  ##########
# Connect to the server at IP Address 86.36.35.17
# and port number 15112
socket = StartConnection("86.36.35.17", 15112)

# Ask the user for their login name and password
username = raw_input(">> Login as: ")
if ("Exit" == username) : exit()

password = raw_input(">> Password: ")
if ("Exit" == password) : exit()

# Run authentication
# Ask for username and password again if incorrect
while not login (socket, username, password):
    print ">> Incorrect Username/Password Combination!"
    print ">> Please try again, or type 'Exit' to close the application."
    username = raw_input(">> Login as: ")
    if ("Exit" == username) : exit()
    password = raw_input(">> Password: ")
    if ("Exit" == password) : exit()

# Now user is logged in

# Set up your commands options
menu = {
        "Menu": PrintUsage,
        "Users" : ShowUsers,
        "Friends": ShowFriends,
        "Add Friend": AddFriend,
        "Accept Friend": AcceptFriend,
        "Send Message": SendMessage,
        "Send File": SendFile,
        "Requests": ShowRequests,
        "Messages": ShowMessages,
        "Score": ShowScore
    }

# Prompt the user for a command
print ">> Welcome", username, "!"
print ">> Insert command or type Menu to see a list of possible commands"
prompt = "[" + username + "]>>"
command = raw_input(prompt)

while (command != "Exit"):
    if not command in menu.keys():
        print ">> Unidentified command " + command + ". Please insert valid command or type Menu to see a list of possible commands."
        prompt = "[" + username + "]>>"
        command = raw_input(prompt)
    else:
        menu[command](socket)
        command = raw_input(prompt)
