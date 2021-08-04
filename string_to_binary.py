
def string2bin(string):
    return ''.join(bin(ord(c)) for c in string).replace('b','')
# utility function 
def strToBinary(s):   # To Convert a 2 charcters into 16 bit of binary data
    bin_conv = [] 
  
    for c in s: 
          
        # convert each char to 
        # ASCII value 
        ascii_val = ord(c) 
          
        # Convert ASCII value to binary 
        binary_val = bin(ascii_val) 
        bin_conv.append(binary_val[2:]) 
    z= (' '.join(bin_conv)) 
    

    s="0"
    q=0
    for i in range(len(z)):
        #s='{0:016b}'.format(z[i])
        if z[i] !=' ':
            
            s+=str(z[i])
            q+=1
        else:
            q=0
            l=len(s)
            if l>8:
                l=l-8
                p='0'*(8-l)
            else:
                p='0'*(8-l)
            s=p+s
    if(q<8):
        p='0'*(9-l)
        s= s[:8]+p+s[8:]

    
    return(s)
          
    
  
# Driver Code 
if __name__ == '__main__': 
    
    s=input("Enter your binary string: ")
    #print(val)
    z=strToBinary(s) 
       
    print(z)


#print("Script written by:   Kshitij Kumar Singh 2018124")



    