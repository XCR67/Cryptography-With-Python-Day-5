#DAY 5 - AES / RSA ENCRYTION
#Before starting, open the shell tool in the sidebar and type pip install PyCryptodome
#and press enter, then import the dependencies. Only import AES and token_bytes for now,
#We will import RSA when we do asymmetric encryption
from Crypto.Cipher import AES
from secrets import token_bytes
import rsa
key = token_bytes(16) #Make key

#Encrypts the message with 128-bit encryption
def encrypt(msg):
  #Make cipher based off key and AES mode as well as create nonce variable
  cipher = AES.new(key, AES.MODE_EAX)
  nonce = cipher.nonce
  #Make the encrypted text as well as a verification tag
  cipherTxt, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
  #Return the nonce, cipherTxt, and verification tag
  return nonce, cipherTxt, tag

#Decrypts cipherTxt using the nonce, cipherTxt and tag
def decrypt(nonce, cipherTxt, tag):
  cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
  
  plainTxt = cipher.decrypt(cipherTxt)
  #This will be used to verify the message, will crash if it can't verify it
  cipher.verify(tag)
  #Return the plainTxt
  return plainTxt.decode('ascii')
  
#Tests
nonce, cipherTxt, tag = encrypt(input("Enter a secret message: "))
print(cipherTxt)
plainTxt = decrypt(nonce, cipherTxt, tag)
print(plainTxt)



#Asymmetric Encryption
#Before starting, open the shell tool in the sidebar and type pip install rsa
#and press enter, then import the dependency.
#import rsa #Note this will be underneath the other 2 dependency downloads
#Private and Public key are made
publicKey, privateKey = rsa.newkeys(2048) #Either 2048 or 4096, must be one of these two
#The keys are saved onto a .pem file which is viewable in the sidebar
#Click on the .pem files on the side to show them off, making usre to note the private
#key would normally never be shared and would not be laying around in a .pem file,
#but rather in a ssecure location
with open("public.pem", "wb") as f:
  f.write(publicKey.save_pkcs1("PEM"))
with open("private.pem", "wb") as f:
  f.write(privateKey.save_pkcs1("PEM"))

#Assigning a private and public key variable which we'll use by getting the values
#from the .pem files. You can comment out the code above to prevent a new key to
#be made with each run of the program
with open("public.pem", "rb") as f:
  pubk = rsa.PublicKey.load_pkcs1(f.read())
with open("private.pem", "rb") as f:
  privk = rsa.PrivateKey.load_pkcs1(f.read())
#Encrypt the message in the console
message = input("Enter a message to encrypt: ")
encryptedmessage = rsa.encrypt(message.encode(), pubk)
print(encryptedmessage)
#This makes a txt file of the encrpted message in the sidebar
with open("encmessage.txt", "wb") as f:
  f.write(encryptedmessage)
print("-----End of Encrypt Test 1-----")
#Test 2 - Decrypt the message in console
decryptedmessage = rsa.decrypt(encryptedmessage, privk)
print(decryptedmessage.decode())
print("-----End of Encrypt Test 2-----")
#Test 3 - Decrypting from encmessage.txt
encryptedmessage3 = open("encmessage.txt", "rb").read()
clearmessage = rsa.decrypt(encryptedmessage3, privk)
print(clearmessage)#You can type clearmessage.decode() to get rid of the b''
print("-----End of Encrypt Test 3-----")

#Step 3 - Encryption Signing with the private key
message = input("Enter a message to sign: ")
#SHA-256 is an algorithm that is used to generate the signature
signature = rsa.sign(message.encode(), privk, "SHA-256")
#This makes a txt file of the signed message in the
#sidebar, note that this isnt encrypting persay, just verifying it
#originated from you
with open("signedmessage.txt", "wb") as f:
  f.write(signature)
##Test 1 - Verify the signed text file came from you
with open("signedmessage.txt", "rb") as f:
  signature = f.read()
#If it prints SHA-256 then it means it came from you
#as it shares the algorithm used to sign it
print(rsa.verify(message.encode(), signature, pubk))
print("-----End of Sign Test 1-----")
#Test 2 - Verify the signed text file came from you with an altered message
alteredmessage = message #+ "A string that changes the original message"
with open("signedmessage.txt", "rb") as f:
  signature = f.read()
#This will always error, so comment it out after demonstration to continue the lesson
print(rsa.verify(alteredmessage.encode(), signature, pubk))
print("-----End of Sign Test 2-----")
