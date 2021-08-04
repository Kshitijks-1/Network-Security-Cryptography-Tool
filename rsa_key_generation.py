import math
def modular_inverse(a, m):
	m0 = m
	y = 0
	x = 1
	if (m == 1):
		return 0
	while (a > 1):
		
		q = a // m # q is quotient
		t = m
		# m is remainder now
		# Now process same as Euclid's algorithm
		m = a % m
		a = t
		t = y
		y = x - q * y  # Update x and y
		x = t

	
	if (x < 0):   # x should be always positive
		x = x + m0

	return x


def rsa_key_gen(z,p,q,N):
   
    phi=(p-1)*(q-1)
    N=p*q
    
    e=2
    while(e<phi):
        if(math.gcd(e,phi)==1):
            break
        else:
            e+=1
   
    d=modular_inverse(e,phi)
    print(z+" Private Key(d) is: ",d,N)
    print(z+" Public Key(e) is: ",e,N)

    w=str(e)+' '+str(d)

    return w



def main():
	
  
	p=int(input("Enter prime number p: "))
	q=int(input("Enter prime number q: "))
	#msg="101 52 102 53 56 97 56 48 53 97 54 101 49 102 100 48 102 54 98 101 102 53 56 99 56 54 102 57 99 101 98 51 "
	print(rsa_key_gen("Server",p,q))


if __name__=="__main__":

    main()

#print("Script written by:   Kshitij Kumar Singh 2018124")



