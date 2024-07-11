import string
import random
import os
import sys
import hashlib
# TASK 1
def ds_hash(message: str) -> int:
    hash_value = 0
    for ch in message:
        hash_value = (hash_value * 71) + ord(ch)

    return hash_value & 0x7FFFFFFF

def myAttack() -> bool:
# YOUR IMPLEMENTATION
    #creates the values for creating the random string that will be used for the hash function
    size=64
    str = string.ascii_uppercase+string.ascii_lowercase+string.digits
    #creating an epmty list for the random hash values to be stored in
    list = [] #This creates a new list that will chich which hash values are equal
    bo = True #boolean for when there is a collison 
    #loops until theere is a collision
    while bo != False:
        #creates a random string with the length of size and consists of lowercase, uppercase and numbers
        hashRand = "".join(random.choice(str) for _ in range(size))
        #uses the ds_hash fuction that takes the hashRand value and stores the output into the randHash value
        #having the random hash values that will be used to check if there are any collisons 
        randHash = (ds_hash(hashRand))
        #This adds the randHash value into the list of random hash values
        list.append(randHash)
    

    #This will loop through all of the values in the list and will check to see if the vlaues is in the newlist and if it is then
    #The value bo will be set to True and if not then it will be set to False
    #Ture meaning tht there is a collison and False meaning that there are no collisons
        for x in list:
            if x in list:
                bo = False
            else:
                bo = True
#print the result of the function 
    if bo == True:
        return True
    if bo ==False:
        return False
    # True or False

#TASK 2
def CustomHMAC(key: bytes, text: str) -> str:
# YOUR IMPLEMENTATION
    B = 64 # Byte size for the values
    L = 32 # Byte lengh of hash outputs
    if len(key) > B:
        #if the key is bigger than the lengh of the block then it will hash it so it is smaller 
        key = hashlib.sha256(key).digest()
        key = key + bytes([0x00] * (B - len(key)))
        print(len(key))
    elif len(key) < B:
        #else if it is too small then it will padd the rest of it after the key with zeros
        key = key + bytes([0x00] * (B - len(key)))  
        print(len(key))


    ipad = bytes([0x36]*B) #creating the inner padding to be added to the text 
    opad = bytes([0x5c]*B) #creates the outer padding to be added to the text 
    
    ipadxor = bytes(a^b for a, b in zip(key,ipad)) #xor operation on the bytes in K and ipad for the second step 

    #textApp = #adds the text that is encoded into bytes so it can be added to the ipadxor value and be saved as textapp
    innerH = hashlib.sha256(ipadxor + text.encode()).digest()#uses the hashlib libaray and makes an instace of a sha256 hashing  
   # H.update(textApp) #uses the Hash function to update itself with the textapp value creating a hash value for it 

    opadxor = bytes(a^b for a, b in zip(key,opad)) # xor operation that is done with teh opad and K to get the outer padding for this function 

    #step6 =  #for step 6 where the vale of the hashed ipadxor is appened to the end of the opandxor so the whole string can be hashsed giving the final result 

    outerH = hashlib.sha256(opadxor+innerH).hexdigest() #creating another instance of the hashlib sha256 for the last step of the program 
    #H.update(step6) #updates the H hash function with the fully padded value to get the last value where it can be digested for the output

    return outerH # YOUR RESULT


#TASK 3
# -- START OF YOUR CODERUNNER SUBMISSION CODE
# INCLUDE ALL YOUR IMPORTS HERE
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
def CustomAESMode(key: bytes, iv: bytes, plaintext: str) -> str:
# YOUR IMPLEMENTATION    
    #this uses an AES encryption algorithm using ECB mode to carry out a CBC cipher block chaining encryption where the IV and a chunk of the plain text will be XOR 
    #the result of the XOR will then be inputted into the encrytion algorithm and it will keep doing this untill all of the plain text has been encrypted 


    cipher = Cipher(algorithms.AES(key), modes.ECB())#creates the instance of the cipher algorithm with the AES in ECB mode 
    encryptor = cipher.encryptor() #makes the encripter part of the algorithm 
    plaintext = bytes(plaintext,'utf-8') #converting the plain text to bytes so it can be XOR 
    paddingLen = 16 - (len(plaintext)% 16) #if the palintext is not 16 byteslong then it will need to be padded for the XOR  
    paddedPlainText = plaintext + bytes([paddingLen]*paddingLen) #padds the plain text if it is too short for an XOR
    BL = [paddedPlainText[i:i+16] for i in range(0, len(paddedPlainText),16)] #gets the blocks which are 16 bytes long 
    xor = iv #renaming iv so it will use it for only the firt one until it gets overwritten 
    xor = [bytes(a^b for a, b in zip(bl,xor))for bl in BL] #performs the XOR on all of the chunks of the plain text in a loop 


    cipherText = b'' #creating an empty cipherText for all of the blocks to be stored in 
    for x in xor: #loop tthrough all of the cipher blocks 
        B = encryptor.update(x) #adds the encrypted blocks and uses the encrypter made earier to encrypt the data in the blocks 
        cipherText+=B #appends the ciphered blocks into the cipherText Variable 

    return cipherText.hex() # returns the cipherText 
# -- END OF YOUR CODERUNNER SUBMISSION CODE

if __name__ == "__main__":
    #print( myAttack() )
    #k = os.urandom(16) # k is <class 'bytes'>
    #txt = "hello world!!!!" # txt is <class 'str'>
    #print( CustomHMAC(k, txt) )
    key = bytes.fromhex("06a9214036b8a15b512e03d534120006")
    iv = bytes.fromhex("3dafba429d9eb430b422da802c9fac41")
    txt = "This is a text"
    print( CustomAESMode(key, iv, txt) )
