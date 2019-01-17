'''
Encrypts existing files in an S3 bucket

Created on Nov 8, 2018

@author: bhoff
'''
import json
import os
import argparse
import boto3

def s3Encrypt(bucketName, key, s3Client):
    acl = s3Client.get_object_acl(Bucket=bucketName, Key=key)
    acl.pop('ResponseMetadata', None)
    s3Client.copy_object(CopySource={'Bucket': bucketName, 'Key': key}, Bucket=bucketName, Key=key, ServerSideEncryption='AES256')
    s3Client.put_object_acl(Bucket=bucketName, Key=key, AccessControlPolicy=acl)
    
def encryptBucket(awsKeyId, awsKeySecret, awsSessionToken, bucket, maxKeysPerBatch, startAfter, maxNumberToProcess, dryrun):
    if awsKeyId is None and awsKeySecret is None:
        # This is the case in which the script is running on an EC2 having a role.  See "IAM Role" here: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html
        s3Client= boto3.client('s3')
    else:  
        s3Client= boto3.client('s3', aws_access_key_id=awsKeyId, aws_secret_access_key=awsKeySecret, aws_session_token=awsSessionToken)
    
    counter=0
    unencrypted=0
    continuationToken=None
    while True:
        if continuationToken is None:
            if startAfter is None:   
                objs = s3Client.list_objects_v2(Bucket=bucket, MaxKeys=maxKeysPerBatch)
            else:
                objs = s3Client.list_objects_v2(Bucket=bucket, StartAfter=startAfter, MaxKeys=maxKeysPerBatch)
        else:
            objs = s3Client.list_objects_v2(Bucket=bucket, ContinuationToken=continuationToken, MaxKeys=maxKeysPerBatch)
        contents = objs.get('Contents')
        continuationToken = objs.get('NextContinuationToken')
        if contents is None or len(contents)==0:
            break
        i = 0
        while i<len(contents) and (maxNumberToProcess is None or counter<maxNumberToProcess):
            key = contents[i]['Key']
            try:
                objectMeta = s3Client.head_object(Bucket=bucket, Key=key)
                sse = objectMeta.get('ServerSideEncryption')
                if sse == 'AES256':
                    print(key+'\tServerSideEncryption: '+sse+"\tNo encryption necessary")
                else:
                    unencrypted=unencrypted+1
                else:
                    if not dryrun:
                        s3Encrypt(bucket, key, s3Client)
                    print(key+'\t encrypted using ServerSideEncryption')
            except Exception as e:
                print(key+'\t'+str(e))
            i = i + 1
            counter = counter + 1
        if maxNumberToProcess is not None and counter>=maxNumberToProcess:
            break
        if continuationToken is None:
            break

    print("Processed "+str(counter)+" files ("+unencrypted+" unencrypted files were found), ending with "+key+".")
    return key

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bucket", required=True, help="bucket name")
    parser.add_argument("-kid", "--awsKeyId", required=False, help="AWS Key ID")
    parser.add_argument("-ksec", "--awsKeySecret", required=False, help="AWS Key Secret")
    parser.add_argument("-awstoken", "--awsSessionToken", required=False, help="AWS MFA Session Token")
    parser.add_argument("-m", "--maxNumberToProcess", type=int, help="Maximum number of files to process", required=False)
    parser.add_argument("-d", "--dryrun", action='store_true', help="dry run")
    parser.add_argument("-s", "--startAfter", required=False, help="the last key successfully processed")
    args = parser.parse_args()
    encryptBucket(args.awsKeyId, args.awsKeySecret, args.awsSessionToken, args.bucket, 200, args.startAfter, args.maxNumberToProcess, args.dryrun)
