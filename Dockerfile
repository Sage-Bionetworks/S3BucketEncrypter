FROM python:3.6

RUN pip install nose
RUN pip install boto3

COPY . /S3BucketEncrypter

WORKDIR /S3BucketEncrypter

