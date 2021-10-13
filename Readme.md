## **Simplified AES Implementation**
***

Code is working as Expected.
To run python 3.7 should be installed
and command 
#### ***python3 client.py*** or 
#### ***python3 server.py***  should be used.

## Input client side
Two prime number should be input for RSA key generation and then secret key and plain text should be entered

## Input Server Side
Two prime numbers should be input for RSA key generation.

There is  Basic Socket Programming which simply sends the strings from client to the server in the same pc or same network until server is closed message could be send by running client file.
In server.py there is server.listen() and handle_client() which works as recieving data from client until client sends **DISCONNECT** message.

In client.py it has send() function which sends the data to server

There are two files client.py and server.py
**client.py** first takes p&q prime numbers and generates its public and private key.
Similarly **server.py** takes p&q prime numbers and generates its public key and private key. Server Public key is sent to client and it is used for encryption of it's input secret key.
So fist encrypted secret key is send followed by client public key and client signature then cipher text is sent 2 letters at a time. 
client signature is generated after hashing the input plain text and then applying RSA using client private key. It is used for verification of its sender.


**client.py**  will take Plain Text of any size without special characters as input and Cipher key as Binary input in 16 bit size and encrypt it  and send the cipher text and key to the server through **socket programming**. **client.py** has encrypt() function which encrypts the plain text.
In Plain Text space was creating few issues so every space in plain text is replaced with 'z' and later while printng all 'z' is replaced with space at decrypt function.

**server.py** will receive the cipher text and key over the channel  and will decrypt it and display the output. ***server.py*** has decrypt() function which decrypts according to S-AES algorithm

Both Client and Server file have **key()** fuction which will expand the keys to 3 keys.
A lot of Bit Shift operator is used in encrypt() and decrypt() function .



In client side whole plain text is stored and at a time 2 letters is converted into 16 bit binary using **string_to_binary.py** file and then it is encrypted and sent. At server side using decrypt function it is converted back to 16 bits then by using **binary_to_string.py** back to those 2 letters. Now it is printed and stored until whole plain text is sent.

Finally the whole Plain Text is printed at server side. 

***

## **Brief about functions in server.py**
## Isub is an array used for inverse substituion. It recieves 4 bit binary input
### Print(s)
 This recieves string and print space for all 'z' in the string

###  hashdig(msg)
This is used for hashing the input plain text

### Print(s)
Used for Replacing all 'z' with ' '


### mult(p1, p2)
This multiplies two binary numbers in GF.


### iMixCol(s) 
This do mix coloumn operation while decrypting.
### Rot(s)
This recieves 16 bit binary input and swaps 4-8th bits with 0-4th bits.

### key(k)
This recieves a key of 16 bit binary input and expands into 3 keys using process defined in S-AES algorithm

### decrypt(p)
This recieves ciphertext in 16 bit binary form and perform 2 rounds as described in S-AES algo

### Sub3(s)
This receives 16 bit binary input and substiute 8-16 bits of it using Isbox(Inverse substitution array)
### Sub4(s)
This receives 16 bit binary input and substiute 8-16 bits of it using isbox(Inverse substitution array)


### rsadecrypt(d,N,msg):
This is used for RSA decryption using key as 'd' and modulas 'N'  of message 'msg'


### intToVec(n):
This Convert a 2-byte integer into a 4-element vector

### vecToInt(m):
This Convert a  4-element vector into a 2-byte integer 
***

## **Brief about functions in client.py**
#### sub is an array used for substituion. It recieves 4 bit binary input
### replace_spaces(s)
This function replaces all spaces in plain text with 'z'

###  hashdig(msg)
This is used for hashing the input plain text

### Rot(s)
This recieves 16 bit binary input and swaps 4-8th bits with 0-4th bits.

### Sub(s):
This receives 16 bit binary input and substiute 0-8 bits of it using Sbox(substitution array)

### Sub2(s)
This receives 16 bit binary input and substiute 8-16 bits of it using Sbox(substitution array)

### mult(p1, p2)
This multiplies two binary numbers in GF.

### key(k)
This recieves a key of 16 bit binary input and expands into 3 keys using process defined in S-AES algorithm

### encrypt(s)
This receives 16 bit plain text and encrpyts it into cipher text by performing 2 rounds as described in S-AES algo.

### intToVec(n):
This Convert a 2-byte integer into a 4-element vector

### vecToInt(m):
This Convert a  4-element vector into a 2-byte integer 


### rsaencrypt(e,N,msg)

This does the RSA encyption of message 'msg' using key 'e' and modulas 'N'







![RSA](https://user-images.githubusercontent.com/78027791/137094694-f6d06863-8bd2-49b3-a740-12547592a835.png)










