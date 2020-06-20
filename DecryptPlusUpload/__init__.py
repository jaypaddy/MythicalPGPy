import logging

import azure.functions as func
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pprint import pprint
from azure.storage.blob import BlobServiceClient

class BlobClass(object):
    connection_string = ""
    container_name = ""

    def __init__(self, connStr,containerName):
        self.connection_string = connStr
        self.container_name = containerName

    def download_blob_as_string(self,srcBlob):
        blob_content=""
        # Instantiate a new BlobServiceClient using a connection string
        blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
        # Instantiate a new ContainerClient
        container_client = blob_service_client.get_container_client(self.container_name)
        # Instantiate a new BlobClient
        blob_client = container_client.get_blob_client(srcBlob)
        # [START download_blob]
        download_stream = blob_client.download_blob()
        blob_content = download_stream.readall()
        # [END download_blob]
        return blob_content

    def upload_string_as_blob(self, msg, dstBlob):
        # Instantiate a new BlobServiceClient using a connection string
        blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
        # Instantiate a new BlobClient
        blob_client = blob_service_client.get_blob_client(container=self.container_name, blob=dstBlob)
        blob_client.upload_blob(msg)


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

    ConnStr = "DefaultEndpointsProtocol=https;AccountName=mythicalspa;AccountKey=NGlfooNqhxr6SOl3Xnh8MR8DKpv3OkM4VP9K3TbsOpwPBYHcLjrJafetnwEf4Y+10WK/4yv/MWnxxMyG1udkhg==;EndpointSuffix=core.windows.net"
    srcContainer = "pgpy"

    blobObj = BlobClass(ConnStr, srcContainer)

    #Get the Source Content
    srcFile = 'ec_hremp_cntrycd_dly.dat'
    srcContent = blobObj.download_blob_as_string(srcFile)
    print('Source Length', len(srcContent))
    #Get the PGPObject
    pgpyObj = PGPy("hrecs@123")

    #Get the Private Key
    keyContent = blobObj.download_blob_as_string('private.key')

    #Import Private Key
    key = pgpyObj.import_keys(keyContent)
    print('Imported Private Keys')

    #Decrypt the Content
    decryptedContent = pgpyObj.decrypt_msg(srcContent)
    #upload the Decrypted Blob
    blobObj.upload_string_as_blob(decryptedContent,srcFile+'.DECRYPTED')








    #Get the Private Key
    privatekey = privatekeyblob.read()
    #Get the PGPObject
    pgpyObj = PGPy("hrecs@123")
    #Import Private Key
    key = pgpyObj.import_keys(privatekey)
    #Load into memory Source Content
    srcContent = encryptedblob.read()
    #Decrypt the Content
    decryptedContent = pgpyObj.decrypt_msg(srcContent)
    decryptedblob.set(decryptedContent)