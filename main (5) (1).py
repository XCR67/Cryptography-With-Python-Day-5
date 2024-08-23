#DAY 5 - AES / RSA ENCRYTION
#Before starting, open the shell tool in the sidebar and type pip install PyCryptodome
#and press enter, then import the dependencies. Only import AES and token_bytes for now,
#We will import RSA when we do asymmetric encryption
#from Crypto.Cipher import AES
#from secrets import token_bytes
#import rsa

#AES ENCRYPTION
#Make key

#Encrypts the message with 128-bit encryption
#def encrypt(msg):
  #Make cipher based off key and AES mode as well as create nonce variable

  #Make the encrypted text as well as a verification tag

  #Return the nonce, cipherTxt, and verification tag


#Decrypts cipherTxt using the nonce, cipherTxt and tag
#def decrypt(nonce, cipherTxt, tag):
  #Makes a cipher that can decrypt the cipherTxt
  
  #This will be used to verify the message, will crash if it can't verify it

  #Return the plainTxt
  
#Tests



#RSA Encryption
#Before starting, open the shell tool in the sidebar and type pip install rsa
#and press enter, then import the dependency.
#import rsa #Note this will be underneath the other 2 dependency downloads

#Private and Public key are made, either 2048 or 4096, must be one of these two

#The keys are saved onto a .pem file which is viewable in the sidebar
#Click on the .pem files on the side to show them off, making usre to note the private
#key would normally never be shared and would not be laying around in a .pem file,
#but rather in a secure location

#Assigning a private and public key variable which we'll use by getting the values
#from the .pem files. You can comment out the code above to prevent a new key to
#be made with each run of the program

#Encrypt the message in the console

#This makes a txt file of the encrpted message in the sidebar

#Test 2 - Decrypt the message in console

#Test 3 - Decrypting from encmessage.txt


#Encryption signing with the private key

#SHA-256 is an algorithm that is used to generate the signature

#This makes a txt file of the signed message in the
#sidebar, note that this isnt encrypting persay, just verifying it
#originated from you

##Test 1 - Verify the signed text file came from you

#If it prints SHA-256 then it means it came from you
#as it shares the algorithm used to sign it

#Test 2 - Verify the signed text file came from you with an altered message
#i.e., add a random string to the actual message

#NOTE - A failed verification atempt always errors so comment it out when you dont want to deal with it
#Thats it!
