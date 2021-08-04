def convert(p):
    return (bytes.fromhex(p).decode('utf-8'))   # Convert the hexdecimal to letters

def main():
    s=input("Enter your hexadecimal value as string: ")
    k=convert(s[2:])
    print(k)

if __name__=="__main__":

    main()

#print("Script written by:   Kshitij Kumar Singh 2018124")
