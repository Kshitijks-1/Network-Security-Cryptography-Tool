from client import rsaencrypt
import socket
import threading
from binary_to_string import convert
import hashlib
from sympy import *
from rsa_key_generation import rsa_key_gen

sub = [0x9, 0x4, 0xa, 0xb, 0xd,0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]  #Substitution Box
Isub = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf, 0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]  #Inverse Substitution Box

def hashdig(msg): 
    # Hashing function to generate message digest
    
    #print()
    digi = hashlib.md5(msg.encode())   # Using MD5 Hashing Algorithm
    x=digi.hexdigest()
    #print(x)
    return x


def Print(s):                  # Print function to replace all 'z' with space ' ' 
    q=' '
    lov=""
    for i in range(len(s)):
        if s[i]=='z':
            lov+=q
        else:
            lov+=s[i]

    return lov
def Sub(s): # This Fuction gives the substituted form of the binary input for first 0-8 bits of 16 bit binary input
    return (sub[(s&0x00f0)>>4]<<4 | sub[s&0x000f])
    
            


def iMixCol(s):           # This function perform the inverse mix column operation
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]

def Rot(s):                # This fucntion swaps the 0-4th bit with 5-8th bits of 16 bit binary input
    return (((s<<4)&0x00f0) | ((s>>4)&0x000f))

def Sub3(s):               # This Fuction gives the substituted form of the binary input for first 0-8 bits of 16 bit binary input
    return (Isub[(s&0x00f0)>>4]<<4 | Isub[s&0x000f])
def Sub4(s):               # This Fuction gives the substituted form of the binary input for first 9- 16 bits of 16 bit binary input
    return (Isub[(s&0xf000)>>12]<<12 | Isub[(s&0x0f00)>>8]<<8)  

def intToVec(n):            # Convert a 2-byte integer into a 4-element vector
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            
 
def vecToInt(m):            # Convert a 4-element vector into 2-byte inte
    """Convert a 4-element vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]




def mult(p1, p2):   # Multiply two polynomials in GF(2^4)/x^4 + x + 1
    
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111


def key(k):         # This fucntion generates 3 keys of input 16 bit binary key
    
    global k0
    global k1
    global k2

    s0 = (k&0xf000)>>12   # Extracting last 12-15th bits of 16 bit bianry input
    s1 = (k&0x0f00)>>8    # Extracting last 11-8th bits of 16 bit bianry input
    s2 = (k&0x00f0)>>4    # Extracting last 4-7th bits of 16 bit bianry input
    s3 = (k&0x000f)       # Extracting last 0-3 bits of 16 bit bianry inpu
    w0 = (s0<<4 | s1)     # Gives 8 bit half part of key K0
    w1 = (s2<<4 | s3)     # Gives another half 8 bit of key K0
    k0 = (w0<<8 | w1)     # This is Key K0
    s4 =  Rot(w1)
  

    s5 =  Sub(s4)
    
    w2 = w0 ^ (0x0080)    # Performing operations as described in S-AES algo
    w2 = w2 ^ s5
    w3 = w2 ^ w1
    w4 = w2 ^ (0b00110000) ^ Sub(Rot(w3))
    w5 = w4 ^ w3  
    k1 = w2<<8 | w3        # This is Key k1
    k2 = w4<<8 | w5        # This is Key k2
   

def decrypt(p):
    
    p8 = p ^ k2            # This is pre Round Transformation
    #print("After Pre-round transformation: ",hex(p8))
    #print("Round key K2:  ",hex(k2))
    
    s0 = (p8&0xf000)>>12
    s1 = (p8&0x0f00)>>8
    s2 = (p8&0x00f0)>>4
    s3 = (p8&0x000f)
    q = s1
    s1 = s3
    s3 = q 
    p9 = (s0<<12 | s1<<8) | (s2<<4 | s3) #Round 1 InvShift rows
    #print("After Round 1 InvShift rows: ",hex(p9))
    

    p10=(Sub4(p9) | Sub3(p9)) #Inversse Substitution                              
    #print("After Round 1 InvSubstitute nibbles: ",hex(p10))
    

    p11 = p10 ^ k1      #  Round 1 InvAdd round key
    #print("After Round 1 InvAdd round key: ",hex(p11))
    #print("Round key K1: ",hex(k1))  # Round 1 Key
    
    p12 = vecToInt(iMixCol(intToVec(p11)))   #Round 1 InvMix columns
    #print("After Round 1 InvMix columns: ",hex(p12))
  
    s0 = (p12&0xf000)>>12
    s1 = (p12&0x0f00)>>8
    s2 = (p12&0x00f0)>>4
    s3 = (p12&0x000f)
    q = s1
    s1 = s3
    s3 = q 
    p13 = (s0<<12 | s1<<8) | (s2<<4 | s3) # Round 2 InvShift rows
    #print("After Round 2 InvShift rows: ",hex(p13))
   
    p14=(Sub4(p13) | Sub3(p13))  # Round 2 InvSubstitute nibbles
    #print("After Round 2 InvSubstitute nibbles: ",hex(p14))
    
    global p15

    p15 = p14 ^ k0 #Round 2 Add round key
    #print("After Round 2 Add round key: ",hex(p15))
    #print("Round Key K0: ",hex(k0))   #Round Key K0




    #print("Plain Text: ",hex(p15))  # The Decrypted Plain Text in binary form
    f=convert(str(hex(p15))[2:])    # The Decrypted Plain Text in letter form
    return f


def rsadecrypt(d,N,msg):     # RSA decryption Function
    f=msg.split()
    
    r=""
    for i in f:
        #print(type(i))
        k=int(i)
        r+=chr(pow(k,d,N))
    return r
    


HEADER = 2048
PORT = 9999
FORMAT='utf-8'
DISCONNECT = "!DISONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
print(SERVER)
ADDR = (SERVER , PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

v = 1
p1=0
q1=0
while v == 1:
    p1=int(input("Enter first prime number(p): "))   # for input of 2 prime numbers p&q for RSA algorithm
    q1=int(input("Enter first prime number(q): "))
    
    if isprime(p1) and isprime(q1) :
        break



def handle_client(conn, addr):     # This function is for New Connections
    print(f"[NEW CONNECTION] {addr} connected..")   # When anyone connects
    connected = True
    global Key
    global cipher
    q=1
    k=1
    w = ""
    N=p1*q1
    
    s_key = rsa_key_gen("Server",p1,q1,N).split()     # Generating the Private and Public key by RSA key Generation
    spub = int(s_key[0])   # Since key was recieved as string so converting it to integer
    spri = int(s_key[1])
    se=""
    
    se = str(spub)+' '+str(N)
    #print("Server public Key sent...")
    print()
    conn.send(se.encode(FORMAT))          # Sending the Server Public Key to Client
    #msgl=conn.recv(HEADER).decode(FORMAT)    
    '''

    if msgl:
        print("Encrypted Secret Key is Received...")
        print(conn.recv(HEADER).decode(FORMAT))
    msgl=conn.recv(HEADER).decode(FORMAT)
   

    if msgl:
        print("Encrypted Secret Key is Received...")
        print(conn.recv(HEADER).decode(FORMAT))
    '''
    q=0
    cpub=0
    cpri=0
    cN=0
    en_scr_key=""
    length = 0


    while connected:  # Until the connection is not closed it will not break
           
        msg_length = conn.recv(HEADER).decode(FORMAT)  
        if msg_length: # If non zero lenth of message is recieved
           
            msg_length = int(msg_length) 
            # Converting the message i.e binary string  into integer
        
            

            if q==0:
                
                msg = (conn.recv(msg_length).decode(FORMAT))    # For Receiving the Encrypted Secret Key
                
                #print("\n Encrypted Secret Key is Received...")
                #print(msg)

                en_scr_key = rsadecrypt(spri,N,msg)   # decrypting to obtain the secret key to be used in AES algorithm

                #print()
                

                Key=int(en_scr_key,2)   # Using the secret key for AES variant algorithm

                key(Key)

                #print()
                #print("Input Cipher key: ",hex(Key))
                #print()

            elif q==1:
                
                msg = (conn.recv(msg_length).decode(FORMAT))      # Obtaining the client Public key
                #print("\n Client Public Key is Received... ",msg)

                ce=msg.split()
                cpub=int(ce[0])
                cN=int(ce[1])

             
           

            elif q==2:
                msg = (conn.recv(msg_length).decode(FORMAT))      # For Client Signature to be Received and Decrypted to obtain digest
                #print("Client Signature is Received...")
                #print(msg)
                #print()
                #print("Client Public key is...",cpub,cN)
                digest_decrypted = rsadecrypt(cpub,cN,msg)

                #print()
                
                #print()



            elif q==3:
                msg = (conn.recv(msg_length).decode(FORMAT))
                length=int(msg)
                #print("Length of message to be recieved is...",length)
                #print()
               
            


            else:
                
                msg = int((conn.recv(msg_length).decode(FORMAT)),2)
                cipher=msg
                w+=decrypt(cipher) 
                if len(w) == length:           # For Matching the length of the message recieved with length sent
                    print("Decrypted Secret Key: ",en_scr_key)
                    
                    
                    
                    if w[length-1]=='z':
                        w= w[0:length-1]
                    w = Print(w)
                    
                    print("Decrypted Message: ",w)
                    print("Message Digest obtained from Client Signature: ",digest_decrypted)
                    msg_digest = hashdig(w)                 

                    print("Intermediate Verification Code: ",msg_digest)   


                    if(msg_digest==digest_decrypted):
                        print("Signature Verified...")
                    else:
                        print("Signature Not Verified...")

                    print()


                    break
                #Print(w)
            q+=1
            
            '''
            if q % 2==0:                             # To ensure that Both key and Cipher text is recieved processing doesn't starts
                Key=(u)
                print("Input Cipher key: ",hex(Key)) # When Cipher Key is received 
                                    
            else:
                cipher=(u)
                print("Input Cipher Text: ",hex(cipher)) # When Cipher Text is received 
                
            if q % 2==0:                              # When both key and cipher text is recieved decryption starts

                key(Key)
                #print("Server side...")
               
                   
            q+=1
            Print(w)
            '''
            #conn.send("Message Recieved".encode(FORMAT))                           # Chunks of plain text i.e 2 characters batches recieved so far is printed and when all of cipher text is received final plain text is printed                                                                          
            if w==DISCONNECT:                         # to Close the connection
                connected=False
        
        
        

        

    conn.close()    # For closing the Connection

    print("Server is closed...")
    print("Script written by:   Kshitij Kumar Singh 2018124")

def main():

    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        #print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

if __name__=="__main__":
    main()

#print("Script written by:   Kshitij Kumar Singh 2018124")
