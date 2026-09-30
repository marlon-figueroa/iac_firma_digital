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


import base64
import json
import uuid

sqs = boto3.client("sqs")
ORIGIN = os.environ["CORS_ORIGIN"]
QUEUE = os.environ["QUEUE_URL"]
UNSIGNED = os.environ["UNSIGNED_PREFIX"]


def response(code, payload):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": ORIGIN},
        "body": json.dumps(payload),
    }


def handler(event, context):
    try:
        raw = event.get("body") or ""
        if event.get("isBase64Encoded"):
            data = base64.b64decode(raw)
            if not data:
                return response(400, {"error": "PDF vacio"})
            doc_id = str(uuid.uuid4())
            s3.put_object(Bucket=BUCKET, Key=f"{UNSIGNED}{doc_id}.pdf", Body=data, ContentType="application/pdf")
            out = sign_bytes(doc_id, data)
        elif raw.startswith("{"):
            clave = json.loads(raw)["clave"]
            doc_id = clave.rsplit("/", 1)[-1][:-4]
            data = s3.get_object(Bucket=BUCKET, Key=clave)["Body"].read()
            out = sign_bytes(doc_id, data)
        else:
            return response(400, {"error": "envie application/pdf o JSON con clave"})
        return response(200, {"id": doc_id, "clave": out})
    except Exception as exc:
        print(f"fallo: {exc}")
        try:
            sqs.send_message(QueueUrl=QUEUE, MessageBody=json.dumps({"error": str(exc)[:500]}))
        except Exception as send_exc:
            print(f"cola: {send_exc}")
        return response(500, {"error": "no se pudo firmar"})
