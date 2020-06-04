import logging

import azure.functions as func
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pprint import pprint

class PGPy(object):
    recipients = []
    pgpKey = pgpy.PGPKey()

    def __init__(self, passPhrase):
        self.passphrase = passPhrase
        
    def decrypt_msg(self, msg):
        emsg = pgpy.PGPMessage.from_blob(msg)
        with self.pgpKey.unlock(self.passphrase):
           deCryptedmsg = self.pgpKey.decrypt(emsg)
        return str(deCryptedmsg.message)

    def encrypt_msg(self,msg):
        emsg = pgpy.PGPMessage.new(msg)
        enCryptedmsg = self.pgpKey.encrypt(emsg)
        return str(enCryptedmsg)

    def import_keys(self,key):
        # download from Blob - to be replaced with KeyVault
        key, _ = pgpy.PGPKey.from_blob(key)
        self.pgpKey = key
        return key

def main(inputblob: func.InputStream,
         privatekeyblob: func.InputStream,
         publickeyblob: func.InputStream,
         outputblob: func.Out[func.InputStream]):
    logging.info(f"Python blob trigger function processed blob \n"
                 f"Name: {inputblob.name}\n"
                 f"Blob Size: {inputblob.length} bytes")
  
    publicKey = publickeyblob.read().decode("utf-8") 
    logging.info(publicKey)
    privatekey = privatekeyblob.read().decode("utf-8") 

    #Get the PGPObject
    pgpyObj = PGPy("AmericanAirlines")
    #Import Public Key
    key = pgpyObj.import_keys(publicKey)
    #Load into memory Source Content
    srcContent = inputblob.read().decode("utf-8")
    #Encrypt the Content
    encryptedContent = pgpyObj.encrypt_msg(srcContent)
    outputblob.set(encryptedContent)