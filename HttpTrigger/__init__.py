import logging

import azure.functions as func


def main(req: func.HttpRequest,
         privatekeyblob: func.InputStream,
         publickeyblob: func.InputStream) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')


    privatekeyfilename = "private.key"
    publickeyfilename = "public.key"
    publicKey = publickeyblob.read().decode("utf-8") 
    logging.info(publicKey)
    privatekey = privatekeyblob.read().decode("utf-8") 


    return func.HttpResponse(f"Hello {publicKey}!")
   