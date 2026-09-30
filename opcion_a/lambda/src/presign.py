import json
import os
import uuid

import boto3

s3 = boto3.client("s3")
BUCKET = os.environ["BUCKET"]
PREFIX = os.environ["UNSIGNED_PREFIX"]
ORIGIN = os.environ["CORS_ORIGIN"]


def handler(event, context):
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": ORIGIN,
    }
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": "JSON invalido"})}
    if body.get("nombre") and not str(body["nombre"]).endswith(".pdf"):
        return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": "el nombre debe terminar en .pdf"})}
    doc_id = str(uuid.uuid4())
    key = f"{PREFIX}{doc_id}.pdf"
    url = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": BUCKET, "Key": key, "ContentType": "application/pdf"},
        ExpiresIn=900,
    )
    payload = {"id": doc_id, "clave": key, "url": url, "expiraEn": 900, "contentType": "application/pdf"}
    return {"statusCode": 200, "headers": headers, "body": json.dumps(payload)}
