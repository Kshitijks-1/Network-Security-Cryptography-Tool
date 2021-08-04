import socket
from string_to_binary import strToBinary 
import hashlib
from sympy import *
from rsa_key_generation import rsa_key_gen

sub = [0x9, 0x4, 0xa, 0xb, 0xd,0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]  #Substitution Box
x=""

def hashdig(msg):  
    # Hash Function used for hashing
    
    print()
    digi = hashlib.md5(msg.encode())   # Using MD5 Hashing Algorithm
    x=digi.hexdigest()
    #print(x)
    return x


def replace_spaces(s):       # Replaces all spaces with 'z' in the input plain text
    return s.replace(" ","z")


def Rot(s):      # This fucntion swaps the 0-4th bit with 5-8th bits of 16 bit binary input
    return (((s<<4)&0x00f0) | ((s>>4)&0x000f))
def Sub(s): # This Fuction gives the substituted form of the binary input for first 0-8 bits of 16 bit binary input
    return (sub[(s&0x00f0)>>4]<<4 | sub[s&0x000f])
def Sub2(s): # This Fuction gives the substituted form of the binary input for first 9- 16 bits of 16 bit binary input
    return (sub[(s&0xf000)>>12]<<12 | sub[(s&0x0f00)>>8]<<8)

def intToVec(n): # Convert a 2-byte integer into a 4-element vector
    
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            
 
def vecToInt(m): # Convert a 4-element vector into 2-byte integer
    
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]




def mult(p1, p2): # Multiply two polynomials in GF(2^4)/x^4 + x + 1
    
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111

def mixCol(s): # This function perform the mix column operation
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]    

def key(k): # This fucntion generates 3 keys of input 16 bit binary key
    
    global k0
    global k1
    global k2

    s0 = (k&0xf000)>>12 # Extracting last 12-15th bits of 16 bit bianry input
    s1 = (k&0x0f00)>>8  # Extracting last 11-8th bits of 16 bit bianry input
    s2 = (k&0x00f0)>>4  # Extracting last 4-7th bits of 16 bit bianry input
    s3 = (k&0x000f)     # Extracting last 0-3 bits of 16 bit bianry input
    w0 = (s0<<4 | s1)   # Gives 8 bit half part of key K0
    w1 = (s2<<4 | s3)   # Gives another half 8 bit of key K0
    k0 = (w0<<8 | w1)   # This is Key K0
    s4 =  Rot(w1)       
    

    s5 =  Sub(s4)
    
    w2 = w0 ^ (0x0080)  # Performing operations as described in S-AES algo
    w2 = w2 ^ s5
    w3 = w2 ^ w1
    w4 = w2 ^ (0b00110000) ^ Sub(Rot(w3))
    w5 = w4 ^ w3 
    k1 = w2<<8 | w3    # This is Key k1
    k2 = w4<<8 | w5    # This is Key k2
    

def encrypt(p):
    
    p = p ^ k0  # This is pre Round Transformation
    #print("After Pre-round transformation: ",hex(p))
    #print("Round key K0: ",hex(k0))

    p1=(Sub2(p) | Sub(p))   #Substitution
    #print("After Round 1 Substitute nibbles: ",hex(p1))

    
    s0 = (p1&0xf000)>>12    # Extracting last 12-15th bits of 16 bit of p1
    s1 = (p1&0x0f00)>>8     # Extracting last 11-8th bits of 16 bit of p1
    s2 = (p1&0x00f0)>>4     # Extracting last 7-4th bits of 16 bit of p1
    s3 = (p1&0x000f)        # Extracting last 0-3th bits of 16 bit of p1
    q = s1                  #  Swapping
    s1 = s3                 #       
    s3 = q                  #
    p2 = (s0<<12 | s1<<8) | (s2<<4 | s3)          # Round 1 Shift Rows
    #print("After Round 1 Shift Rows: ",hex(p2))
    

    p3 = vecToInt(mixCol(intToVec(p2)))           # Round 1 Mix Coloumns
    #print("After Round 1 Mix Coloumns: ",hex(p3))
    
   

    p4 = p3 ^ k1
    #print("After Round 1 Add Round key: ",hex(p4)) # Round 1 Add Round key
     

    ###### Round 2 starts  ##########
    #print("Round key K1: ",hex(k1))

    p5=(Sub2(p4) | Sub(p4))   #Substitution
    #print("After Round 2 Substitute nibbles: ",hex(p5))

    s0 = (p5&0xf000)>>12          # Extracting last 12-15th bits of 16 bit of p5
    s1 = (p5&0x0f00)>>8           # Extracting last 11-8th bits of 16 bit of p5
    s2 = (p5&0x00f0)>>4           # Extracting last 7-4th bits of 16 bit of p5
    s3 = (p5&0x000f)              # Extracting last 0-3th bits of 16 bit of p1
    q = s1                        # Swapping                          
    s1 = s3
    s3 = q 
    p6 = (s0<<12 | s1<<8) | (s2<<4 | s3)        # Round 2 Shift rows
    #print("After Round 2 Shift rows: ",hex(p6))

   
    global p7
    p7 = p6 ^ k2
    #print("After Round 2 Add round key: ",hex(p7))  # Round 2 Add round key
    #print("Round Key K2: ",hex(k2))
    #print("Cipher Text: ", hex(p7))                  # Cipher Text 
    return p7


def rsaencrypt(e,N,msg):
    cip=""
    #original=""
    for i in msg:
        w=ord(i)
        #original+=str(w)+" "
        cip+=str(pow(w,e,N))+" "

    #print("Original message is: ",original)
    return cip


def main():
    v = 1
    while v == 1:      # for taking prime number p&q as input as key Parameters
        p1=int(input("Enter first prime number(p): "))
        q1=int(input("Enter first prime number(q): "))
        if (isprime(p1) and isprime(q1)) :
            break
    cN=p1*q1
    cl_key = rsa_key_gen("Client",p1,q1,cN).split()   #Generating the Client Private and Public Key
    print()
    cpub = int(cl_key[0])
    cpri = int(cl_key[1])
    
    ce=str(cpub)+ ' ' + str(cN)
    
    HEADER = 2048
    PORT = 9999
    FORMAT='utf-8'
    DISCONNECT = "!DISONNECT"
    SERVER = socket.gethostbyname(socket.gethostname())
    ADDR = (SERVER,PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    # print("Requesting Server for public key...")
    #print()
    se=(client.recv(HEADER).decode(FORMAT))     # Receiving the Server Public from Server
    qw=se.split()
    spub=int(qw[0])
    sN=int(qw[1])

    #print("Server Public Key Received is: ",qw[0],qw[1])
    #print()

    def send(msg):           # Send Function
        message = msg.encode(FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' '*(HEADER-len(send_length))
        client.send(send_length)
        client.send(message)
    
    

    
        
    your_msg1 = input("Enter your key: ")           #16 Bit Binary key taken input like 0110011100111011
    
    your_msg2 = input("Enter your plain text: ")   # Any Length of plain Text without any special characters as input like "Hi I am Kshitij"
    
    print()
    print("Message: ",your_msg2)
    print("Secret Key: ",your_msg1)
    #print("Client Public Key: ",cpub,cN)
    #print("Client Private Key: ",cpri,cN)


    hashdigest = (hashdig(your_msg2))
    cl_sig = rsaencrypt(cpri,cN,hashdigest)     # Evaluating the client signature


    en_scr_key = rsaencrypt(spub,sN,your_msg1)
    print("Encrypted Secret Key: ",en_scr_key)
    send(en_scr_key)                # Sending The Encrypted Secret Key 
    
    
    #print("sent encrypted secret key...")
    
    #print()

    send(ce)    # Sending The Client Public Key
    #print("Client Public Key is sent...")

   

    s=len(your_msg2)
    your_msg2=replace_spaces(your_msg2)
    if s%2 !=0:                                       # This is Padding to make input plain Text of even length

        your_msg2+='z'

    #print(your_msg2)
    #send(your_msg1)

    #print()

    send(cl_sig)          # sending the Client Signature to server
    # print()
    #print("Client Signature is sent...",cl_sig)
    #print()


    length=len(your_msg2)

    #print("Length of message is...",length)

    send(str(length))
    
    
    #print("Client Side...")
    cipher=""
    for i in range(0,len(your_msg2),2):               # This Loop ensures that at a time 2 characters are encrypted and sent
        d=""
        
        d+=your_msg2[i]+your_msg2[i+1]                # Extracting ith and i+1th character
        #print(i,d)
        f=strToBinary(d)                              # Converting to 16 Bit Binary form of 2 characters of input plain text
        
        
        key(int(your_msg1,2))                         # Calling key()  fucntion for key generation
        p=encrypt(int(f,2))                           # Encrypting those 2 characters
        cipher+=str(hex(p))[2:]                       # Cipher Text been stored to be printed at last
        z=bin(p) 
        
        e = str(z)
        send(z[2:])                                   # Encrypted Cipher text sent over channel in binary form
        #send(your_msg1)                               # key being sent over the channel             
        i = 2
        if i>len(your_msg2)-1:                        # if not further characater left loop breaks
            break
    
    print("Cipher Text: ",cipher)
    print("Digest: ",hashdigest)
    print("Client Signature: ",cl_sig)
    print("Script written by:   Kshitij Kumar Singh 2018124")

    


    

if __name__=="__main__":

    main()

#print("Script written by:   Kshitij Kumar Singh 2018124")



