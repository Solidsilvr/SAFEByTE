#Initialisation / Pre-Setups
import sqlite3,hashlib,secrets,base64,pickle,os,time
from cryptography.fernet import Fernet
from prettytable import PrettyTable

#Runtime calculator:
stime=time.perf_counter()

#Function Defs:
def dbcnct():
    os.makedirs("data",exist_ok=True)
    global Db,Dc
    Db=sqlite3.connect("data/Psuedo.db")
    Dc=Db.cursor()
    Dc.execute("Create table Seneor (Password Varchar(256) Primary key)")
    Dc.execute("Create table seneorita (S_no integer Primary Key Autoincrement,Domain varchar(256) Not Null,Username varchar(256) Not Null,Password varchar(256) Not Null)")
    Db.commit()

def srhfltrprt():
    global table2
    print("|------------------------------------------------------------------------------|\n")
    if len(bytes(table2).decode()) == 159:
        table2[:] = b'\x00' * len(table2)
        del table2
        print("\t\t\t| No Such Records found |")
    else:
        print(bytes(table2).decode())
        table2[:] = b'\x00' * len(table2)
        del table2
    print("\n|------------------------------------------------------------------------------|\n")
    input("Continue: ")

#Registration
def Reg():
    while True:
        P=bytearray(input("Enter Password: "),"utf-8")
        PC=bytearray(input("Confirm Password: "),"utf-8")
        if P == PC: #Password Match-up confirmation
            S=secrets.token_bytes(16) #Generating random bytes for salt generation
            f3=open("data/Pepper.dat","wb")
            pickle.dump(S.hex(),f3)
            f3.close()
            Dc.execute("insert into Seneor values(?)",(hashlib.pbkdf2_hmac('sha256',bytes(P),S,10000,32).hex(),)) #Inserting Hashed Password to database
            print("| Registration Success |")
            print("Records inserted succesfuly\n \t| Login |")
            Db.commit()
            P[:]= PC[:] = b'\x00' * len(P)
            break
        else:
            print("| Password confirm mismatch | \n\t Try Again")
            continue
    
#User Login/Main Loop
def Login():
    while True:
        P=bytearray(input("Enter Password: "),"utf-8")
        PC=bytearray(input("Confirm Password: "),"utf=8")
        if P == PC: #Password Match-up confirmation
            Dc.execute("Select Password from Seneor")
            Px=Dc.fetchone()[0]
            f3=open("data/Pepper.dat","rb")
            S=pickle.load(f3)
            f3.close()
            if secrets.compare_digest(hashlib.pbkdf2_hmac('sha256',bytes(P),bytes.fromhex(S),10000,32).hex(),Px): #Comapring both passwords 
                print("  | Succesful Login |\n")
                F=Fernet(base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',bytes(P),bytes.fromhex(S),10000,32))) #Encryption Object
                P[:]= PC[:] = b'\x00' * len(P)
                table=PrettyTable()
                while True:
                    try:
                        Dc.execute("Select * from seneorita order by S_no")
                        rec=Dc.fetchall()
                        print("|------------------------------------------------------------------------------|\n")
                        if rec == []:
                            print("\t\t\t| No Passwords Stored Yet |")
                            Sn=1
                        else:
                            table.clear()
                            table.field_names=["S_no","Domain","Username","Password"]
                            for x in rec:
                                table.add_row([x[0],F.decrypt(bytes.fromhex(x[1])).decode(),F.decrypt(bytes.fromhex(x[2])).decode(),F.decrypt(bytes.fromhex(x[3])).decode()])  #Decrypting / Displaying Records
                                Sn=x[0]+1
                            print(table)
                        print("\n|------------------------------------------------------------------------------|")
                        print("\n| Pick a choice |\n1: Add record\n2: Delete record\n3: Change record\n4: Search record\n5: Additional Settings\n6: Save & Quit")
                        ch=int(input("Enter your choice: "))
                        if ch == 1:
                            Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                            Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()      #Encrypting and storing Information
                            Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                            Dc.execute("insert into seneorita values(?,?,?,?)",(Sn,Domain,Usi,Pai))
                            print("Successfuly inserted record\n")
                        elif ch == 2:
                            n=int(input("Input the Sn. of the record you wish to delete: "))      #Deleting records
                            Dc.execute("Delete from seneorita where S_no = ?",(n,))
                            print("Record succesfuly deleted\n")
                        elif ch == 3:
                            Sn=int(input("Input the Sn. of the record you wish to change: "))     #Altering Records
                            print("Please re-enter the following information\n")
                            Domain=F.encrypt(input("Enter the Domain of registraion: ").encode()).hex()
                            Usi=F.encrypt(input("Enter the username for the domain: ").encode()).hex()
                            Pai=F.encrypt(input("Enter the Password for the domain: ").encode()).hex()
                            Dc.execute("update Seneorita set Domain =?,Username=?,Password=? where S_no = ?",(Domain,Usi,Pai,Sn))
                            print("Successfuly changed record\n")
                        elif ch == 4:
                            print("| Search Record |")
                            print("1: Search by Domain\n2: Search by Username\n3: Go Back")
                            s=int(input("Enter your choice: "))
                            global table2
                            if s == 1:
                                shx=input("Enter the Domain to search: ")
                                table2=bytearray(table.get_string(row_filter=lambda row: row[1]==shx),"utf-8")
                                srhfltrprt()
                            elif s == 2:
                                shx=input("Enter the Username to search: ")
                                table2=bytearray(table.get_string(row_filter=lambda row: row[2]==shx),"utf-8")
                                srhfltrprt()
                            elif s == 3:
                                pass
                            else:
                                print(" | Invalid Input | \n     Try Again")   
                        elif ch == 5:
                            print("| Adittional Settings |")
                            print("1: Change Master Password\n2: Delete Account\n3: Go Back")
                            s=int(input("Enter your choice: "))
                            if s == 1:
                                while True:
                                    P=bytearray(input("Enter New Password: "),"utf-8")
                                    PC=bytearray(input("Confirm Password: "),"utf-8")
                                    if P == PC:
                                        S=secrets.token_bytes(16) #Generating random bytes for salt generation
                                        f3=open("data/Pepper.dat","wb")
                                        pickle.dump(S.hex(),f3)
                                        f3.close()
                                        Dc.execute("Delete from Seneor")
                                        Dc.execute("insert into Seneor values(?)",(hashlib.pbkdf2_hmac('sha256',bytes(P),S,10000,32).hex(),)) #Inserting Hashed Password to database
                                        Db.commit()
                                        print("| Successfuly Altered Password |\n \tLogging Out")
                                        Dc.execute("Select * from seneorita order by S_no")
                                        rec=Dc.fetchall()
                                        if rec != []:
                                            F2=Fernet(base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256',bytes(P),S,10000,32))) #Encryption Object
                                            P[:]= PC[:] = b'\x00' * len(P)
                                            Dc.execute("Delete from Seneorita")
                                            for x in rec:
                                                Dc.execute("insert into seneorita values(?,?,?,?)",(x[0],F2.encrypt(F.decrypt(bytes.fromhex(x[1]))).hex(),F2.encrypt(F.decrypt(bytes.fromhex(x[2]))).hex(),F2.encrypt(F.decrypt(bytes.fromhex(x[3]))).hex()))   
                                            Db.commit()
                                            f2=open("data/Hex.dat","wb")
                                            f4=open("data/Psuedo.db","rb")
                                            pickle.dump(hashlib.file_digest(f4,"sha256").hexdigest(),f2)
                                            f4.close()
                                            f2.close()
                                            del F2
                                        break                                  
                                    else:
                                        print("| Password confirm mismatch | \n\t Try Again")
                                        continue
                                break
                            elif s == 2:
                                Dc.execute("Drop table seneorita")
                                Dc.execute("Drop table Seneor")
                                os.remove("data/Pepper.dat")
                                Db.commit()
                                print("| Account Deleted Successfuly |\n \t| Quitting |")
                                return True
                            elif s == 3:
                                pass
                            else:
                                print(" | Invalid Input | \n     Try Again")
                        elif ch == 6:
                            Db.commit()
                            print(" | Saved: Quitting |\n--------------------\n   SAFEByTE 0.2.5 \n--------------------")
                            table.clear()
                            del(F,table,P,PC)
                            return True
                        else:
                            print(" | Invalid Input | \n     Try Again")
                    except ValueError: # Input Error Handling
                        print(" | Invalid Input | \n ! Enter Numbers !")
                        continue
                break
            else:
                print("    |  Wrong Password  |")
                continue
        else:
            print("| Password confirm mismatch | \n\t Try Again")
            continue

#File/Database integrity verification and Database intialisation
if not os.path.exists("data/Psuedo.db"):    
    print("┌──[ SAFEByTE ]───────────────────────────────────┐\n│                                                 │\n│   > VERIFYING DATABASE INTEGRITY...             │\n│   > |                               |   0%      │\n│                                                 │\n│   > DBFILE     : NOTFOUND                       │\n│                                                 │\n│                                                 │\n│                                                 │\n│                                                 │\n│               [ ACCESS DENIED ]                 │\n│                                                 │\n└─────────────────────────────────────────────────┘\n")
    In=input("Create a new Database\n| YES  or Quit |\n\t")
    if In in ("YES","yes","Yes","Y","y"):
        if os.path.exists("data/Hex.dat"):
            os.remove("data/Hex.dat")
        if os.path.exists("data/Pepper.dat"):
            os.remove("data/Pepper.dat")
        dbcnct()
    elif In in ("QUIT","quit","q","Q","Quit"):
        quit() 
    else:
        print(" | Invalid Input | \n     | Quitting |")
        quit()
else:
    f1=open("data/Psuedo.db","rb")
    NewHex=hashlib.file_digest(f1,"sha256").hexdigest().encode()
    f1.close()
    if not os.path.exists("data/Hex.dat"):
        print("┌──[ SAFEByTE ]───────────────────────────────────┐\n│                                                 │\n│   > VERIFYING DATABASE INTEGRITY...             │\n│   > ███████                         | 25%       │\n│                                                 │\n│   > DBFILE     : FOUND                          │\n│   > HASHFILE   : NOTFOUND                       │\n│                                                 │\n│                                                 │\n│                                                 │\n│               [ ACCESS DENIED ]                 │\n│                                                 │\n└─────────────────────────────────────────────────┘\n")
        In=input("Create a new Database\n| YES  or Quit |\n\t")
        if In in ("YES","yes","Yes","Y","y"):
            os.remove("data/Psuedo.db")
            if os.path.exists("data/Pepper.dat"):
                os.remove("data/Pepper.dat")
            dbcnct()
        elif In in ("QUIT","quit","q","Q"):
            quit() 
        else:
            print(" | Invalid Input | \n     | Quitting |")
            quit()
    else:
        f2=open("data/Hex.dat","rb")
        try:
            X=pickle.load(f2).encode()
        except:
            X=b'0'
        f2.close()
        if secrets.compare_digest(X,NewHex):
            if not os.path.exists("data/Pepper.dat"):
                print("┌──[ SAFEByTE ]───────────────────────────────────┐\n│                                                 │\n│   > VERIFYING DATABASE INTEGRITY...             │\n│   > ███████████████████████         |  75%      │\n│                                                 │\n│   > DBFILE     : FOUND                          │\n│   > HASHFILE   : FOUND                          │\n│   > HASHDIGEST : VERIFIED                       │\n│   > SALT       : NOTFOUND                       │\n│                                                 │\n│               [ ACCESS DENIED ]                 │\n│                                                 │\n└─────────────────────────────────────────────────┘\n")
                In=input("Create a new Database\n| YES  or Quit |\n\t")
                if In in ("YES","yes","Yes","Y","y"):
                    os.remove("data/Psuedo.db")
                    os.remove("data/Hex.dat")
                    dbcnct()
                elif In in ("QUIT","quit","q","Q"):
                    quit() 
                else:
                    print(" | Invalid Input | \n     | Quitting |")
                    quit()
            else:
                Db=sqlite3.connect("data/Psuedo.db")
                Dc=Db.cursor()
                print("┌──[ SAFEByTE ]───────────────────────────────────┐\n│                                                 │\n│   > VERIFYING DATABASE INTEGRITY...             │\n│   > ████████████████████████████████ 100%       │\n│                                                 │\n│   > DBFILE     : FOUND                          │\n│   > HASHFILE   : FOUND                          │\n│   > HASHDIGEST : VERIFIED                       │\n│   > SALT       : FOUND                          │\n│                                                 │\n│               [ ACCESS GRANTED ]                │\n│                                                 │\n└─────────────────────────────────────────────────┘\n")
        else:
            print("┌──[ SAFEByTE ]───────────────────────────────────┐\n│                                                 │\n│   > VERIFYING DATABASE INTEGRITY...             │\n│   > ███████████████                 |  50%      │\n│                                                 │\n│   > DBFILE     : FOUND                          │\n│   > HASHFILE   : FOUND                          │\n│   > HASHDIGEST : FAILED                         │\n│                                                 │\n│                                                 │\n│               [ ACCESS DENIED ]                 │\n│                                                 │\n└─────────────────────────────────────────────────┘\n")
            In=input("Create a new Database\n| YES  or Quit |\n\t")
            if In in ("YES","yes","Yes","Y","y"):
                os.remove("data/Psuedo.db")
                os.remove("data/Hex.dat")
                if os.path.exists("data/Pepper.dat"):
                    os.remove("data/Pepper.dat")
                dbcnct()
            elif In in ("QUIT","quit","q","Q"):
                quit() 
            else:
                print(" | Invalid Input | \n     | Quitting |")
                quit()

 # Program Loop
while True:
    if os.path.exists("data/Pepper.dat"):
        if Login():
            break
        else:
            continue
    else:
        Reg()
        if Login():
            break
        else:
            continue

#Deinitialisation
Dc.close()    
Db.close()
f2=open("data/Hex.dat","wb")
f4=open("data/Psuedo.db","rb")
pickle.dump(hashlib.file_digest(f4,"sha256").hexdigest(),f2)
f4.close()
f2.close()
print(f"Runtime: {time.perf_counter() - stime} seconds.")
quit()

"""
 █████    █████   █████   ███████  ██████   ██    ██ ████████ ██████
██       ██   ██  ██      ██       ██   ██  ██    ██    ██    ██
███████  ███████  █████   █████    ██████     ████      ██    █████
     ██  ██   ██  ██      ██       ██   ██     ██       ██    ██
██████   ██   ██  ██      ███████  ██████      ██       ██    ███████

                                                                  v0.2.5
Github.com/Solidsilvr                                                """
