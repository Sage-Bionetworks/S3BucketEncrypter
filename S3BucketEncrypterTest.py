'''
Tests S3BucketEncrypter

To run

python S3BucketEncrypterTest.py -b <bucketName> \
-skid xxx -sksec xxxx -sawstoken xxxxx \
-ekid xxx -eksec xxxx -eawstoken xxxxx


@author: bhoff
'''
import json
import os
import argparse
import boto3
import random, string
from S3BucketEncrypter import encryptBucket, encryptOneFile


def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))


def createFile(name, bucket, s3Client):
        body = bytearray(randomword(1000), 'utf-8')
        metadata={"meta-name":"meta-"+name}
        s3Client.put_object(Bucket=bucket, Body=body, Key=name, ACL='public-read-write', Metadata=metadata)

def checkFile(bucket, key, expectedAcl, s3Client):
    print("Checking "+key)
    obj = s3Client.get_object(Bucket=bucket, Key=key)
    # verify file is encrypted
    assert obj.get('ServerSideEncryption')=='AES256', key+" is not encrypted"
    # verify that metadata is preserved
    expectedMeta={"meta-name":"meta-"+key}
    assert obj.get('Metadata')==expectedMeta, "Unxpected metadata: "+obj.get('Metadata')
    # verify that permissions and ownership are preserved
    currentAcl = s3Client.get_object_acl(Bucket=bucket, Key=key)
    assert currentAcl['Owner']==expectedAcl['Owner'], "Owner has changed from\n"+json.dumps(expectedAcl['Owner'])+"\nto\n"+json.dumps(currentAcl['Owner'])
    assert currentAcl['Grants']==expectedAcl['Grants'], "Grants have changed from\n"+json.dumps(expectedAcl['Grants'])+"\nto\n"+json.dumps(currentAcl['Grants'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bucket", required=True, help="bucket name")
    parser.add_argument("-skid", "--setup_awsKeyId", required=True, help="AWS Key ID for account which creates the files")
    parser.add_argument("-sksec", "--setup_awsKeySecret", required=True, help="AWS Key Secret for account which creates the files")
    parser.add_argument("-sawstoken", "--setup_awsSessionToken", required=False, help="AWS MFA Session Token for account which creates the files")
    parser.add_argument("-ekid", "--encrypt_awsKeyId", required=True, help="AWS Key ID for the account which encrypts the files")
    parser.add_argument("-eksec", "--encrypt_awsKeySecret", required=True, help="AWS Key Secret for the account which encrypts the files")
    parser.add_argument("-eawstoken", "--encrypt_awsSessionToken", required=False, help="AWS MFA Session Token for the account which encrypts the files")
    parser.add_argument("-m", "--maxNumberToProcess", type=int, help="Maximum number of files to process", required=False)
    parser.add_argument("-d", "--dryrun", action='store_true', help="dry run")
    parser.add_argument("-s", "--startAfter", required=False, help="the last key successfully processed")
    args = parser.parse_args()
    
    s3Client= boto3.client('s3', aws_access_key_id=args.setup_awsKeyId, aws_secret_access_key=args.setup_awsKeySecret, aws_session_token=args.setup_awsSessionToken)

    # available operations for the client:
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html
    
    # create some files with metadata
    keysToDelete = []
    acls = {}
    for i in range(20):
        name = 'file_'+str(i)+'.txt'
        createFile(name, args.bucket, s3Client)
        keysToDelete.append(name)
        acls[name]=s3Client.get_object_acl(Bucket=args.bucket, Key=name)
        
    # run S3BucketEncrypter on bucket
    # Note: user encrypting the files is other than the user who created them
    lastKey = encryptBucket(args.encrypt_awsKeyId, args.encrypt_awsKeySecret, args.encrypt_awsSessionToken, args.bucket, 5, startAfter=None, maxNumberToProcess=10, dryrun=args.dryrun)
    
    print("Now process the rest, starting after "+lastKey)
    lastKey = encryptBucket(args.encrypt_awsKeyId, args.encrypt_awsKeySecret, args.encrypt_awsSessionToken, args.bucket, 5, startAfter=lastKey, maxNumberToProcess=args.maxNumberToProcess, dryrun=args.dryrun)

    for key in keysToDelete:
        checkFile(args.bucket, key, acls[key], s3Client)        
        
    # now set up and encrypt just one file
    name = 'file_singleton.txt'
    createFile(name, args.bucket, s3Client)
    keysToDelete.append(name)
    acl=s3Client.get_object_acl(Bucket=args.bucket, Key=name)
    encryptOneFile(args.encrypt_awsKeyId, args.encrypt_awsKeySecret, args.encrypt_awsSessionToken, args.bucket, name, args.dryrun)
    checkFile(args.bucket, name, acl, s3Client)
    
    print("All files pass checks.")
    
    # tear down
    for key in keysToDelete:
        s3Client.delete_object(Bucket=args.bucket, Key=key)
        
    print("Clean up is done.")
    