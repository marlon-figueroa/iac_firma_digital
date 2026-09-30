import base64
import hashlib
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
kms = boto3.client("kms")
BUCKET = os.environ["BUCKET"]
SIGNED = os.environ["SIGNED_PREFIX"]
KEY_ID = os.environ["KMS_KEY_ID"]


def already(key):
    try:
        s3.head_object(Bucket=BUCKET, Key=key)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
            return False
        raise


def sign_bytes(doc_id, data):
    out = f"{SIGNED}{doc_id}.pdf"
    if already(out):
        return out
    digest = hashlib.sha256(data).digest()
    sig = kms.sign(
        KeyId=KEY_ID,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )["Signature"]
    s3.put_object(
        Bucket=BUCKET,
        Key=out,
        Body=data,
        ContentType="application/pdf",
        Metadata={"firma-sha256": digest.hex(), "firma-kms": base64.b64encode(sig).decode()},
    )
    s3.put_object(Bucket=BUCKET, Key=out + ".sig", Body=sig)
    return out


import json

UNSIGNED = os.environ["UNSIGNED_PREFIX"]
ORIGIN = os.environ["CORS_ORIGIN"]


def handler(event, context):
    done = 0
    token = None
    while done < 20:
        args = {"Bucket": BUCKET, "Prefix": UNSIGNED, "MaxKeys": 20}
        if token:
            args["ContinuationToken"] = token
        page = s3.list_objects_v2(**args)
        for item in page.get("Contents", []):
            key = item["Key"]
            if not key.endswith(".pdf"):
                continue
            doc_id = key.rsplit("/", 1)[-1][:-4]
            data = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
            sign_bytes(doc_id, data)
            done += 1
            if done >= 20:
                break
        if done >= 20 or not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": ORIGIN},
        "body": json.dumps({"procesados": done}),
    }
