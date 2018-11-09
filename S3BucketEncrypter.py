'''
Encrypts existing files in an S3 bucket

Created on Nov 8, 2018

@author: bhoff
'''
import json
import os
import argparse
import boto3

def s3Encrypt(bucketName, key):
    s3Client.copy_object(CopySource={'Bucket': bucketName, 'Key': key}, Bucket=bucketName, Key=key, ServerSideEncryption='AES256')
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bucket", required=True, help="bucket name")
    parser.add_argument("-kid", "--awsKeyId", required=True, help="AWS Key ID")
    parser.add_argument("-ksec", "--awsKeySecret", required=True, help="AWS Key Secret")
    parser.add_argument("-awstoken", "--awsSessionToken", required=False, help="AWS MFA Session Token")
    parser.add_argument("-m", "--maxNumberToProcess", type=int, help="Maximum number of files to process", required=False)
    parser.add_argument("-d", "--dryrun", action='store_true', help="dry run")
    parser.add_argument("-s", "--startKey", required=False, help="first key to examine")
    args = parser.parse_args()

    s3Client= boto3.client('s3', aws_access_key_id=args.awsKeyId, aws_secret_access_key=args.awsKeySecret, aws_session_token=args.awsSessionToken)
    
    counter=0
    firstKey=args.startKey
    while True:
        if firstKey is None:
            objs = s3Client.list_objects(Bucket=args.bucket)
        else:
            objs = s3Client.list_objects(Bucket=args.bucket, Marker=firstKey)
        contents = objs.get('Contents')
        if contents is None or len(contents)==0:
            break
        i = 0
        while i<len(contents) and (args.maxNumberToProcess is None or counter<args.maxNumberToProcess):
            key = contents[i]['Key']
            firstKey=key
            try:
                objectMeta = s3Client.head_object(Bucket=args.bucket, Key=key)
                sse = objectMeta.get('ServerSideEncryption')
                if sse == 'AES256':
                    print(key+'\tServerSideEncryption: '+sse+"\tNo encryption necessary")
                else:
                    if not args.dryrun:
                        s3Encrypt(args.bucket, key)
                    print(key+'\t encrypted using ServerSideEncryption')
            except Exception as e:
                print(key+'\t'+str(e))
            i = i + 1
            counter = counter + 1
        if args.maxNumberToProcess is not None and counter>=args.maxNumberToProcess:
            break

    print("Processed "+str(counter)+" files.")

