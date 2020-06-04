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


def main(encryptedblob: func.InputStream,
         privatekeyblob: func.InputStream,
         publickeyblob: func.InputStream,
         decryptedblob: func.Out[func.InputStream]):
    logging.info(f"Python blob trigger function processed blob \n"
                 f"Name: {encryptedblob.name}\n"
                 f"Blob Size: {encryptedblob.length} bytes")

    #Get the Private Key
    privatekey = privatekeyblob.read().decode("utf-8") 
    #Get the PGPObject
    pgpyObj = PGPy("AmericanAirlines")
    #Import Private Key
    key = pgpyObj.import_keys(privatekey)
    #Load into memory Source Content
    srcContent = encryptedblob.read().decode("utf-8")
    #Decrypt the Content
    decryptedContent = pgpyObj.decrypt_msg(srcContent)
    decryptedblob.set(decryptedContent)