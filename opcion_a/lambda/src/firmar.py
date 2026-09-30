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
from urllib.parse import unquote_plus

UNSIGNED = os.environ["UNSIGNED_PREFIX"]


def handler(event, context):
    failures = []
    for rec in event.get("Records", []):
        try:
            body = json.loads(rec["body"])
            for item in body.get("Records", []):
                key = unquote_plus(item["s3"]["object"]["key"])
                if not key.startswith(UNSIGNED) or not key.endswith(".pdf"):
                    continue
                doc_id = key.rsplit("/", 1)[-1][:-4]
                data = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
                sign_bytes(doc_id, data)
        except Exception as exc:
            print(f"fallo {rec.get('messageId')}: {exc}")
            failures.append({"itemIdentifier": rec["messageId"]})
    return {"batchItemFailures": failures}
