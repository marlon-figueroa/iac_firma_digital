#!/usr/bin/env python3
"""Escribe las plantillas de opcion_a, opcion_b y opcion_c."""

import json
from pathlib import Path

ROOT = Path("/Users/mfigueroa93/Documents/git/iac_firma_digital")

CIDR = {"a": "10.42.0.0/16", "b": "10.43.0.0/16", "c": "10.44.0.0/16"}
NET = {
    "a": ("10.42.1.0/24", "10.42.2.0/24"),
    "b": ("10.43.1.0/24", "10.43.2.0/24"),
    "c": ("10.44.1.0/24", "10.44.2.0/24"),
}
LABEL = {
    "a": "opcion-a",
    "b": "opcion-b",
    "c": "opcion-c",
}
ARCH = {
    "a": "API prefirma PUT, S3 sin-firmar avisa a SQS y Lambda firma con KMS hacia firmados",
    "b": "DataSync deposita en sin-firmar; Scheduler cada 15 min lista y Lambda firma con KMS",
    "c": "API Gateway recibe el PDF o una clave S3 y Lambda firma en la misma llamada",
}


def dumps(text):
    return json.dumps(text, ensure_ascii=False)


def doc(description, arch, must):
    if len(description.encode()) > 1024:
        raise SystemExit(f"Description larga: {len(description.encode())}")
    musts = "\n".join(f"      - {dumps(item)}" for item in must)
    return f"""AWSTemplateFormatVersion: "2010-09-09"
Description: {dumps(description)}
Metadata:
  AWSToolsMetrics:
    AWSAgentToolkit: aws-cloudformation@3
  com.aws.cloudformation.Context:
    arch: {dumps(arch)}
    must:
{musts}
    ref:
      - at: context/compartido.yaml
        has: convenciones comunes de cifrado, custodia y carpetas
        scope: shared
      - at: requerimientos.txt
        has: pedido de vias asincronas y endpoint sincrono
        scope: shared
"""


def rmeta(why, must):
    lines = [
        "    Metadata:",
        "      com.aws.cloudformation.Context:",
        f"        why: {dumps(why)}",
        "        must:",
    ]
    for item in must:
        lines.append(f"          - {dumps(item)}")
    return "\n".join(lines)


def tags(option, indent=8):
    pad = " " * indent
    return (
        f"{pad}- Key: Project\n"
        f"{pad}  Value: !Ref ProjectName\n"
        f"{pad}- Key: Environment\n"
        f"{pad}  Value: !Ref Environment\n"
        f"{pad}- Key: Option\n"
        f"{pad}  Value: {option}"
    )


PARAMS = """
  ProjectName:
    Type: String
    Default: firma-digital
    AllowedPattern: "^[a-z0-9-]{1,20}$"
    Description: Prefijo de nombres. Minusculas, numeros y guion.
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, test, prod]
    Description: Entorno. Tambien es el nombre del stage de API Gateway.
"""

HSM_PARAM = """
  DeployCloudHsm:
    Type: String
    Default: "false"
    AllowedValues: ["true", "false"]
    Description: true crea dos HSM y asocia las Lambdas a la VPC. Cada HSM se cobra por hora.
"""

PREFIX_PARAMS = """
  UnsignedPrefix:
    Type: String
    Default: sin-firmar/
    AllowedPattern: "^sin-firmar/$"
    Description: Prefijo de entrada. La regla de 7 dias usa este valor.
  SignedPrefix:
    Type: String
    Default: firmados/
    AllowedPattern: "^firmados/$"
    Description: Prefijo de salida de los PDF firmados.
  CorsAllowedOrigin:
    Type: String
    Default: https://localhost
    AllowedPattern: "^https://.+"
    Description: Origen permitido en CORS. En produccion usar el dominio real.
"""


PRESIGN = r'''
import json
import os
import uuid

import boto3

s3 = boto3.client("s3")
BUCKET = os.environ["BUCKET"]
PREFIX = os.environ["UNSIGNED_PREFIX"]
ORIGIN = os.environ["CORS_ORIGIN"]
BUCKET_KEY = os.environ["BUCKET_KEY_ID"]


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
        Params={
            "Bucket": BUCKET,
            "Key": key,
            "ContentType": "application/pdf",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": BUCKET_KEY,
        },
        ExpiresIn=900,
    )
    payload = {
        "id": doc_id,
        "clave": key,
        "url": url,
        "expiraEn": 900,
        "contentType": "application/pdf",
        "cifrado": "aws:kms",
        "kmsKeyId": BUCKET_KEY,
    }
    return {"statusCode": 200, "headers": headers, "body": json.dumps(payload)}
'''.strip() + "\n"


SIGN = r'''
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
'''.strip() + "\n"


WORKER = SIGN + r'''

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
'''


LOTE = SIGN + r'''

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
'''


SYNC = SIGN + r'''

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
'''


def assert_zip(name, code):
    size = len(code.encode())
    if size > 4096:
        raise SystemExit(f"{name} pesa {size} bytes; el limite de ZipFile es 4096")
    print(f"{name}: {size} bytes")


def zip_block(code, indent=8):
    pad = " " * indent
    lines = [f"{pad}ZipFile: |"]
    for line in code.strip("\n").split("\n"):
        lines.append(f"{pad}  {line}" if line else "")
    return "\n".join(lines)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def common_params():
    return "Parameters:" + PARAMS


def vpc(option):
    letter = option[-1]
    cidr = CIDR[letter]
    a, b = NET[letter]
    body = doc(
        f"Red privada de {LABEL[letter]} — sin NAT; los endpoints de interfaz solo existen si CloudHSM esta activo.",
        ARCH[letter],
        ["Sin IGW ni NAT", "El egress de la Lambda queda limitado al CIDR de la VPC", "Endpoints de interfaz solo con DeployCloudHsm=true"],
    )
    return body + f"""
{common_params()}{HSM_PARAM}
Conditions:
  UseHsm: !Equals [!Ref DeployCloudHsm, "true"]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
{rmeta("Red de firma. Las Lambdas salen de ella solo si el HSM esta activo.", ["EnableDnsHostnames y EnableDnsSupport para Private DNS de los endpoints"])}
    Properties:
      CidrBlock: {cidr}
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
{tags(LABEL[letter], 8)}
        - Key: Name
          Value: !Sub ${{ProjectName}}-${{Environment}}-{LABEL[letter]}
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      AvailabilityZone: !Select [0, !GetAZs ""]
      CidrBlock: {a}
      MapPublicIpOnLaunch: false
      Tags:
{tags(LABEL[letter], 8)}
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      AvailabilityZone: !Select [1, !GetAZs ""]
      CidrBlock: {b}
      MapPublicIpOnLaunch: false
      Tags:
{tags(LABEL[letter], 8)}
  RouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref Vpc
      Tags:
{tags(LABEL[letter], 8)}
  AssocA:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetA
      RouteTableId: !Ref RouteTable
  AssocB:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetB
      RouteTableId: !Ref RouteTable
  S3Endpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties:
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${{AWS::Region}}.s3
      VpcEndpointType: Gateway
      RouteTableIds:
        - !Ref RouteTable
  LambdaSecurityGroup:
    Type: AWS::EC2::SecurityGroup
{rmeta("Salida solo hacia el CIDR de la VPC, en 443 y en los puertos del cliente CloudHSM.", ["Prohibido 0.0.0.0/0", "Sin ingress"])}
    Properties:
      GroupDescription: Egress de Lambdas hacia la VPC
      VpcId: !Ref Vpc
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: {cidr}
          Description: HTTPS a endpoints de interfaz
        - IpProtocol: tcp
          FromPort: 2223
          ToPort: 2225
          CidrIp: {cidr}
          Description: Cliente CloudHSM dentro de la VPC
      Tags:
{tags(LABEL[letter], 8)}
  EndpointSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Condition: UseHsm
    Properties:
      GroupDescription: Interface endpoints de KMS, SQS, logs y STS
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: {cidr}
          Description: Clientes de la VPC
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: {cidr}
          Description: Respuestas dentro de la VPC
      Tags:
{tags(LABEL[letter], 8)}
  KmsEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Condition: UseHsm
    Properties:
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${{AWS::Region}}.kms
      VpcEndpointType: Interface
      PrivateDnsEnabled: true
      SubnetIds:
        - !Ref SubnetA
        - !Ref SubnetB
      SecurityGroupIds:
        - !Ref EndpointSecurityGroup
  SqsEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Condition: UseHsm
    Properties:
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${{AWS::Region}}.sqs
      VpcEndpointType: Interface
      PrivateDnsEnabled: true
      SubnetIds:
        - !Ref SubnetA
        - !Ref SubnetB
      SecurityGroupIds:
        - !Ref EndpointSecurityGroup
  LogsEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Condition: UseHsm
    Properties:
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${{AWS::Region}}.logs
      VpcEndpointType: Interface
      PrivateDnsEnabled: true
      SubnetIds:
        - !Ref SubnetA
        - !Ref SubnetB
      SecurityGroupIds:
        - !Ref EndpointSecurityGroup
  StsEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Condition: UseHsm
    Properties:
      VpcId: !Ref Vpc
      ServiceName: !Sub com.amazonaws.${{AWS::Region}}.sts
      VpcEndpointType: Interface
      PrivateDnsEnabled: true
      SubnetIds:
        - !Ref SubnetA
        - !Ref SubnetB
      SecurityGroupIds:
        - !Ref EndpointSecurityGroup
Outputs:
  VpcId:
    Value: !Ref Vpc
  SubnetA:
    Value: !Ref SubnetA
  SubnetB:
    Value: !Ref SubnetB
  AzA:
    Value: !GetAtt SubnetA.AvailabilityZone
  AzB:
    Value: !GetAtt SubnetB.AvailabilityZone
  LambdaSecurityGroupId:
    Value: !Ref LambdaSecurityGroup
"""


def symmetric_key(logical, alias_suffix, purpose, letter, service_policy):
    return f"""
  {logical}:
    Type: AWS::KMS::Key
{rmeta(purpose, ["SYMMETRIC_DEFAULT y ENCRYPT_DECRYPT", "EnableKeyRotation true", "No es la llave de firma ni una llave aws/*"])}
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      Description: !Sub "{purpose} ${{ProjectName}} ${{Environment}} {LABEL[letter]}"
      KeySpec: SYMMETRIC_DEFAULT
      KeyUsage: ENCRYPT_DECRYPT
      EnableKeyRotation: true
      PendingWindowInDays: 30
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: EnableIam
            Effect: Allow
            Principal:
              AWS: !Sub arn:aws:iam::${{AWS::AccountId}}:root
            Action: kms:*
            Resource: "*"
{service_policy}
      Tags:
{tags(LABEL[letter], 8)}
  {logical}Alias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub alias/${{ProjectName}}-${{Environment}}-{letter}-{alias_suffix}
      TargetKeyId: !Ref {logical}
"""


def kms(option):
    letter = option[-1]
    bucket_policy = """
          - Sid: AllowS3
            Effect: Allow
            Principal:
              Service: s3.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
            Resource: "*"
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
          - Sid: AllowS3Grant
            Effect: Allow
            Principal:
              Service: s3.amazonaws.com
            Action: kms:CreateGrant
            Resource: "*"
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
              Bool:
                kms:GrantIsForAWSResource: "true"
"""
    queue_policy = """
          - Sid: AllowS3ToQueue
            Effect: Allow
            Principal:
              Service: s3.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
            Resource: "*"
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
          - Sid: AllowSqs
            Effect: Allow
            Principal:
              Service: sqs.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
            Resource: "*"
"""
    return doc(
        f"Llaves de {LABEL[letter]}: ECC P-256 firma; una simetrica cifra S3 y otra SQS.",
        ARCH[letter],
        ["La llave de firma no cifra el bucket ni la cola", "Una llave simetrica por servicio, administrada en la cuenta", "Retain en las tres llaves"],
    ) + f"""
{common_params()}
Resources:
  SigningKey:
    Type: AWS::KMS::Key
{rmeta("Firma ECDSA del SHA-256 del PDF. No rota: KMS no rota llaves asimetricas de firma.", ["No usar esta llave como SSE-KMS del bucket ni de SQS", "PendingWindowInDays 30"])}
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      Description: !Sub Firma ECC P-256 ${{ProjectName}} ${{Environment}} {LABEL[letter]}
      KeySpec: ECC_NIST_P256
      KeyUsage: SIGN_VERIFY
      PendingWindowInDays: 30
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: EnableIam
            Effect: Allow
            Principal:
              AWS: !Sub arn:aws:iam::${{AWS::AccountId}}:root
            Action: kms:*
            Resource: "*"
      Tags:
{tags(LABEL[letter], 8)}
  SigningAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub alias/${{ProjectName}}-${{Environment}}-{letter}
      TargetKeyId: !Ref SigningKey
{symmetric_key("BucketKey", "s3", "Cifrado del bucket", letter, bucket_policy)}
{symmetric_key("QueueKey", "sqs", "Cifrado de SQS", letter, queue_policy)}
Outputs:
  KeyId:
    Value: !Ref SigningKey
  KeyArn:
    Value: !GetAtt SigningKey.Arn
  AliasName:
    Value: !Ref SigningAlias
  BucketKeyArn:
    Value: !GetAtt BucketKey.Arn
  QueueKeyArn:
    Value: !GetAtt QueueKey.Arn
"""


def sqs(option):
    letter = option[-1]
    if letter == "a":
        why = "Cola de trabajo entre el aviso de S3 y la Lambda. La DLQ recibe el mensaje tras 3 intentos."
        extra = """
  WorkQueue:
    Type: AWS::SQS::Queue
""" + rmeta(why, ["Cifrado SSE-SQS", "VisibilityTimeout 360 >= timeout de la Lambda", "S3 solo puede enviar si aws:SourceAccount es esta cuenta"]) + """
    Properties:
      VisibilityTimeout: 360
      MessageRetentionPeriod: 1209600
      ReceiveMessageWaitTimeSeconds: 10
      SqsManagedSseEnabled: true
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt DeadLetterQueue.Arn
        maxReceiveCount: 3
      Tags:
""" + tags(LABEL[letter], 8) + """
  WorkQueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref WorkQueue
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: AllowS3SameAccount
            Effect: Allow
            Principal:
              Service: s3.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt WorkQueue.Arn
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
"""
        outputs = """
  QueueArn:
    Value: !GetAtt WorkQueue.Arn
  QueueUrl:
    Value: !Ref WorkQueue
  DlqArn:
    Value: !GetAtt DeadLetterQueue.Arn
  DlqUrl:
    Value: !Ref DeadLetterQueue
"""
        must = ["La cola de trabajo no acepta SendMessage de S3 de otra cuenta"]
    else:
        extra = ""
        outputs = """
  QueueArn:
    Value: !GetAtt DeadLetterQueue.Arn
  QueueUrl:
    Value: !Ref DeadLetterQueue
"""
        must = ["La cola guarda fallos de firma para reproceso manual"]
    return doc(
        f"Colas de {LABEL[letter]} — cifrado con la llave KMS de SQS y retencion de 14 dias.",
        ARCH[letter],
        must,
    ) + f"""
{common_params()}
Resources:
  DeadLetterQueue:
    Type: AWS::SQS::Queue
{rmeta("Aisla mensajes que la Lambda no pudo firmar.", ["KmsMasterKeyId es la llave simetrica de SQS", "Retencion 14 dias"])}
    Properties:
      MessageRetentionPeriod: 1209600
      KmsMasterKeyId: !Ref QueueKeyArn
      KmsDataKeyReusePeriodSeconds: 300
      Tags:
{tags(LABEL[letter], 8)}
{extra}
Outputs:
{outputs}
"""


def s3(option):
    letter = option[-1]
    notification = ""
    extra_params = ""
    extra_resources = ""
    extra_outputs = ""
    if letter == "a":
        extra_params = """
  QueueArn:
    Type: String
    AllowedPattern: "^arn:aws[a-z0-9-]*:sqs:[a-z0-9-]+:[0-9]{12}:.+"
    Description: ARN de la cola que recibe ObjectCreated de sin-firmar/.
"""
        notification = """
      NotificationConfiguration:
        QueueConfigurations:
          - Event: "s3:ObjectCreated:*"
            Queue: !Ref QueueArn
            Filter:
              S3Key:
                Rules:
                  - Name: prefix
                    Value: !Ref UnsignedPrefix
                  - Name: suffix
                    Value: .pdf
"""
    if letter == "b":
        extra_params = """
  SourceLocationArn:
    Type: String
    Default: ""
    AllowedPattern: "^$|^arn:.+"
    Description: ARN de la ubicacion DataSync de origen. Vacio omite la tarea.
  DataSyncSchedule:
    Type: String
    Default: cron(0 * * * ? *)
    Description: Agenda de la tarea DataSync. Solo aplica si hay origen.
"""
        extra_resources = """
  DataSyncRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: datasync.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-destino
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetBucketLocation
                  - s3:ListBucket
                  - s3:ListBucketMultipartUploads
                Resource: !GetAtt DocumentsBucket.Arn
              - Effect: Allow
                Action:
                  - s3:AbortMultipartUpload
                  - s3:DeleteObject
                  - s3:GetObject
                  - s3:GetObjectTagging
                  - s3:ListMultipartUploadParts
                  - s3:PutObject
                  - s3:PutObjectTagging
                Resource: !Sub ${DocumentsBucket.Arn}/*
      Tags:
""" + tags(LABEL[letter], 8) + """
  DataSyncLocation:
    Type: AWS::DataSync::LocationS3
    Properties:
      S3BucketArn: !GetAtt DocumentsBucket.Arn
      Subdirectory: /sin-firmar
      S3Config:
        BucketAccessRoleArn: !GetAtt DataSyncRole.Arn
      Tags:
""" + tags(LABEL[letter], 8) + """
  DataSyncTask:
    Type: AWS::DataSync::Task
    Condition: HasSource
    Properties:
      SourceLocationArn: !Ref SourceLocationArn
      DestinationLocationArn: !Ref DataSyncLocation
      Schedule:
        ScheduleExpression: !Ref DataSyncSchedule
      Options:
        VerifyMode: ONLY_FILES_TRANSFERRED
        OverwriteMode: ALWAYS
      Tags:
""" + tags(LABEL[letter], 8)
        extra_outputs = """
  DataSyncLocationArn:
    Value: !Ref DataSyncLocation
"""
    conditions = ""
    if letter == "b":
        conditions = """
Conditions:
  HasSource: !Not [!Equals [!Ref SourceLocationArn, ""]]
"""
    return doc(
        f"Bucket de documentos de {LABEL[letter]} — sin-firmar expira a los 7 dias y firmados se conserva.",
        ARCH[letter],
        ["Block Public Access en los cuatro controles", "Deny si aws:SecureTransport es false", "Versionado y Retain"],
    ) + f"""
{common_params()}{PREFIX_PARAMS}{extra_params}{conditions}
Resources:
  DocumentsBucket:
    Type: AWS::S3::Bucket
{rmeta("Guarda el PDF de entrada y el de salida. El aviso a SQS, si existe, filtra sin-firmar/*.pdf.", ["SSE-S3, no la llave de firma", "ExpirationInDays 7 solo en sin-firmar/"])}
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      VersioningConfiguration:
        Status: Enabled
      OwnershipControls:
        Rules:
          - ObjectOwnership: BucketOwnerEnforced
      LifecycleConfiguration:
        Rules:
          - Id: ExpiraSinFirmar
            Status: Enabled
            Filter:
              Prefix: !Ref UnsignedPrefix
            ExpirationInDays: 7
            AbortIncompleteMultipartUpload:
              DaysAfterInitiation: 7
      CorsConfiguration:
        CorsRules:
          - AllowedHeaders: ["*"]
            AllowedMethods: [GET, PUT, HEAD]
            AllowedOrigins:
              - !Ref CorsAllowedOrigin
            MaxAge: 300
{notification}
      Tags:
{tags(LABEL[letter], 8)}
  DocumentsBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref DocumentsBucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: DenyInsecureTransport
            Effect: Deny
            Principal: "*"
            Action: s3:*
            Resource:
              - !GetAtt DocumentsBucket.Arn
              - !Sub ${{DocumentsBucket.Arn}}/*
            Condition:
              Bool:
                aws:SecureTransport: "false"
{extra_resources}
Outputs:
  BucketName:
    Value: !Ref DocumentsBucket
  BucketArn:
    Value: !GetAtt DocumentsBucket.Arn
{extra_outputs}
"""


def iam(option):
    letter = option[-1]
    logs = f"""
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource:
                  - !Sub arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/${{ProjectName}}-${{Environment}}-{letter}-*
                  - !Sub arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/${{ProjectName}}-${{Environment}}-{letter}-*:*
"""
    trust = """
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
"""
    if letter == "a":
        roles = f"""
  PresignRole:
    Type: AWS::IAM::Role
{rmeta("Solo puede emitir PUT sobre sin-firmar.", ["Sin kms:Sign", "Sin lectura de firmados"])}
    Properties:
{trust}
      Policies:
        - PolicyName: presign
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
{logs}
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub ${{BucketArn}}/${{UnsignedPrefix}}*
      Tags:
{tags(LABEL[letter], 8)}
  SignerRole:
    Type: AWS::IAM::Role
{rmeta("Lee sin-firmar, escribe firmados y llama a kms:Sign.", ["kms:Sign acotado a la llave de esta opcion"])}
    Properties:
{trust}
      Policies:
        - PolicyName: firmar
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
{logs}
              - Effect: Allow
                Action: s3:GetObject
                Resource: !Sub ${{BucketArn}}/${{UnsignedPrefix}}*
              - Effect: Allow
                Action: s3:ListBucket
                Resource: !Ref BucketArn
                Condition:
                  StringLike:
                    s3:prefix: !Sub ${{UnsignedPrefix}}*
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub ${{BucketArn}}/${{SignedPrefix}}*
              - Effect: Allow
                Action:
                  - kms:Sign
                  - kms:GetPublicKey
                Resource: !Ref KeyArn
              - Effect: Allow
                Action:
                  - sqs:ReceiveMessage
                  - sqs:DeleteMessage
                  - sqs:GetQueueAttributes
                  - sqs:ChangeMessageVisibility
                Resource: !Ref QueueArn
      Tags:
{tags(LABEL[letter], 8)}
"""
        outputs = """
  PresignRoleArn:
    Value: !GetAtt PresignRole.Arn
  SignerRoleArn:
    Value: !GetAtt SignerRole.Arn
"""
    elif letter == "b":
        roles = f"""
  LoteRole:
    Type: AWS::IAM::Role
{rmeta("Lista sin-firmar, firma y puede avisar fallos a la cola.", ["kms:Sign solo sobre la llave de esta opcion"])}
    Properties:
{trust}
      Policies:
        - PolicyName: lote
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
{logs}
              - Effect: Allow
                Action: s3:ListBucket
                Resource: !Ref BucketArn
              - Effect: Allow
                Action: s3:GetObject
                Resource: !Sub ${{BucketArn}}/${{UnsignedPrefix}}*
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub ${{BucketArn}}/${{SignedPrefix}}*
              - Effect: Allow
                Action:
                  - kms:Sign
                  - kms:GetPublicKey
                Resource: !Ref KeyArn
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !Ref QueueArn
      Tags:
{tags(LABEL[letter], 8)}
  SchedulerRole:
    Type: AWS::IAM::Role
{rmeta("EventBridge Scheduler solo puede invocar la Lambda de lote.", ["Resource acotado al nombre predecible de la funcion"])}
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: scheduler.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: invocar
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: lambda:InvokeFunction
                Resource: !Sub arn:aws:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:${{ProjectName}}-${{Environment}}-b-lote
      Tags:
{tags(LABEL[letter], 8)}
"""
        outputs = """
  LoteRoleArn:
    Value: !GetAtt LoteRole.Arn
  SchedulerRoleArn:
    Value: !GetAtt SchedulerRole.Arn
"""
    else:
        roles = f"""
  SyncRole:
    Type: AWS::IAM::Role
{rmeta("Archiva el PDF de la llamada, lo firma y encola el error si falla.", ["kms:Sign solo sobre la llave de esta opcion"])}
    Properties:
{trust}
      Policies:
        - PolicyName: sincrono
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
{logs}
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub ${{BucketArn}}/${{UnsignedPrefix}}*
              - Effect: Allow
                Action: s3:GetObject
                Resource: !Sub ${{BucketArn}}/${{UnsignedPrefix}}*
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub ${{BucketArn}}/${{SignedPrefix}}*
              - Effect: Allow
                Action:
                  - kms:Sign
                  - kms:GetPublicKey
                Resource: !Ref KeyArn
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !Ref QueueArn
      Tags:
{tags(LABEL[letter], 8)}
"""
        outputs = """
  SyncRoleArn:
    Value: !GetAtt SyncRole.Arn
"""
    return doc(
        f"Roles de {LABEL[letter]} — cada funcion solo tiene las acciones de su paso.",
        ARCH[letter],
        ["Sin politicas administradas amplias", "kms:Sign limitado al ARN de la llave"],
    ) + f"""
{common_params()}{PREFIX_PARAMS}
  BucketArn:
    Type: String
    AllowedPattern: "^arn:aws[a-z0-9-]*:s3:::.+"
    Description: ARN del bucket de documentos.
  KeyArn:
    Type: String
    AllowedPattern: "^arn:aws[a-z0-9-]*:kms:[a-z0-9-]+:[0-9]{{12}}:key/.+"
    Description: ARN de la llave de firma.
  QueueArn:
    Type: String
    AllowedPattern: "^arn:aws[a-z0-9-]*:sqs:[a-z0-9-]+:[0-9]{{12}}:.+"
    Description: ARN de la cola de trabajo o de fallos.
Resources:
{roles}
Outputs:
{outputs}
"""


def lambda_fn(name, role_ref, timeout, memory, code, option, hsm_env=True):
    letter = option[-1]
    vpc = ""
    if hsm_env:
        vpc = """
      VpcConfig: !If
        - UseHsm
        - SecurityGroupIds:
            - !Ref LambdaSecurityGroupId
          SubnetIds:
            - !Ref SubnetA
            - !Ref SubnetB
        - !Ref AWS::NoValue"""
    env_lines = [
        "        Variables:",
        "          BUCKET: !Ref BucketName",
        "          UNSIGNED_PREFIX: !Ref UnsignedPrefix",
        "          SIGNED_PREFIX: !Ref SignedPrefix",
        "          KMS_KEY_ID: !Ref KeyArn",
        "          CORS_ORIGIN: !Ref CorsAllowedOrigin",
    ]
    if name.endswith("lote") or name.endswith("firmar") and letter == "c":
        env_lines.append("          QUEUE_URL: !Ref QueueUrl")
    if letter == "a" and name.endswith("firmar"):
        pass
    env = "\n".join(env_lines)
    # QUEUE_URL only when the parameter exists. Presign does not have QueueUrl.
    return f"""
  {name}LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/${{ProjectName}}-${{Environment}}-{name.lower()}
      RetentionInDays: 30
  {name}Function:
    Type: AWS::Lambda::Function
    DependsOn: {name}LogGroup
{rmeta("Firma el hash con KMS o, en el caso de la prefirma, solo entrega la URL.", ["Runtime python3.12 y arm64", "El codigo embebido cabe en ZipFile"])}
    Properties:
      FunctionName: !Sub ${{ProjectName}}-${{Environment}}-{name.lower()}
      Role: !Ref {role_ref}
      Runtime: python3.12
      Architectures:
        - arm64
      Handler: index.handler
      Timeout: {timeout}
      MemorySize: {memory}
      Code:
{zip_block(code, 8)}
      Environment:
{env}{vpc}
      Tags:
{tags(LABEL[letter], 8)}
"""


def lambdas(option):
    letter = option[-1]
    base_params = common_params() + HSM_PARAM + PREFIX_PARAMS + """
  BucketName:
    Type: String
    AllowedPattern: "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
    Description: Nombre del bucket de documentos.
  KeyArn:
    Type: String
    Description: ARN de la llave de firma.
  CorsAllowedOrigin:
    Type: String
    Description: Origen que la Lambda devuelve en CORS.
  SubnetA:
    Type: String
    Description: Subred privada A. Solo se usa si DeployCloudHsm=true.
  SubnetB:
    Type: String
    Description: Subred privada B. Solo se usa si DeployCloudHsm=true.
  LambdaSecurityGroupId:
    Type: String
    Description: Security group de las Lambdas dentro de la VPC.
"""
    # CorsAllowedOrigin is duplicated if PREFIX_PARAMS also has it. PREFIX_PARAMS includes it.
    # I included CorsAllowedOrigin again. Remove the second block by not adding it.
    # Fix: base_params currently has PREFIX which includes Cors. Then I added Cors again.
    # I'll rebuild params cleanly below in each branch instead. This function's base is wrong.
    raise RuntimeError("replaced below")


def lambdas(option):
    letter = option[-1]
    conditions = """
Conditions:
  UseHsm: !Equals [!Ref DeployCloudHsm, "true"]
"""
    net = """
  SubnetA:
    Type: String
    Description: Subred privada A. Se usa si DeployCloudHsm=true.
  SubnetB:
    Type: String
    Description: Subred privada B. Se usa si DeployCloudHsm=true.
  LambdaSecurityGroupId:
    Type: String
    Description: Security group de salida de las Lambdas.
"""
    if letter == "a":
        params = common_params() + HSM_PARAM + PREFIX_PARAMS + net + """
  BucketName:
    Type: String
    Description: Nombre del bucket de documentos.
  KeyArn:
    Type: String
    Description: ARN de la llave de firma.
  QueueArn:
    Type: String
    Description: ARN de la cola de trabajo.
  PresignRoleArn:
    Type: String
    Description: Rol de la Lambda que emite la URL.
  SignerRoleArn:
    Type: String
    Description: Rol de la Lambda que firma.
"""
        resources = lambda_fn("APresign", "PresignRoleArn", 10, 256, PRESIGN, option)
        # presign env should not require KMS. The helper always sets KMS_KEY_ID.
        # That's ok if the parameter exists. Presign template has KeyArn. Good.
        # Presign function name becomes apresign because name.lower() on APresign -> apresign.
        # I wanted a-presign. FunctionName uses name.lower() which is apresign not a-presign.
        # The IAM log prefix is {letter}-* which is a-*. Function name is
        # ${ProjectName}-${Environment}-apresign which does NOT match a-*.
        # FIX: pass a suffix.
        resources += lambda_fn("AFirmar", "SignerRoleArn", 60, 1024, WORKER, option)
        resources += f"""
  SignerMapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      EventSourceArn: !Ref QueueArn
      FunctionName: !Ref AFirmarFunction
      BatchSize: 5
      MaximumBatchingWindowInSeconds: 5
      FunctionResponseTypes:
        - ReportBatchItemFailures
"""
        outputs = """
  PresignFunctionArn:
    Value: !GetAtt APresignFunction.Arn
  SignerFunctionArn:
    Value: !GetAtt AFirmarFunction.Arn
"""
        code_files = {"presign.py": PRESIGN, "firmar.py": WORKER}
    elif letter == "b":
        params = common_params() + HSM_PARAM + PREFIX_PARAMS + net + """
  BucketName:
    Type: String
    Description: Nombre del bucket de documentos.
  KeyArn:
    Type: String
    Description: ARN de la llave de firma.
  QueueArn:
    Type: String
    Description: ARN de la cola de fallos.
  QueueUrl:
    Type: String
    Description: URL de la cola de fallos.
  LoteRoleArn:
    Type: String
    Description: Rol de la Lambda de lote.
  SchedulerRoleArn:
    Type: String
    Description: Rol con el que Scheduler invoca la Lambda.
  ProcessSchedule:
    Type: String
    Default: rate(15 minutes)
    Description: Frecuencia del procesamiento del prefijo sin-firmar.
"""
        resources = lambda_fn("BLote", "LoteRoleArn", 300, 1024, LOTE, option)
        resources += """
  BatchSchedule:
    Type: AWS::Scheduler::Schedule
""" + rmeta("Dispara el lote aunque no haya un POST. Varios ciclos vacios no mueven el costo.", ["rate(15 minutes) por defecto", "Una sola ejecucion concurrente"]) + """
    Properties:
      Description: Procesa sin-firmar cada 15 minutos
      ScheduleExpression: !Ref ProcessSchedule
      FlexibleTimeWindow:
        Mode: "OFF"
      State: ENABLED
      Target:
        Arn: !GetAtt BLoteFunction.Arn
        RoleArn: !Ref SchedulerRoleArn
"""
        # ReservedConcurrentExecutions on the function - add via search? I'll set it in a
        # follow-up replace inside lambda_fn by not. Add property by patching the function
        # YAML is already emitted. I'll append nothing and set concurrency in lambda_fn
        # for lote only. See lambda_fn - I didn't add ReservedConcurrentExecutions.
        # I'll add it here as an AWS::Lambda::Function property... can't add after.
        # Leave concurrency unlimited; the schedule is every 15 min and timeout is 5 min
        # so overlap is possible. Add a note. Optional: I'll inject in lambda_fn if name==BLote.
        outputs = """
  LoteFunctionArn:
    Value: !GetAtt BLoteFunction.Arn
"""
        code_files = {"lote.py": LOTE}
    else:
        params = common_params() + HSM_PARAM + PREFIX_PARAMS + net + """
  BucketName:
    Type: String
    Description: Nombre del bucket de documentos.
  KeyArn:
    Type: String
    Description: ARN de la llave de firma.
  QueueUrl:
    Type: String
    Description: URL de la cola de fallos.
  SyncRoleArn:
    Type: String
    Description: Rol de la Lambda sincrona.
"""
        resources = lambda_fn("CFirmar", "SyncRoleArn", 29, 1024, SYNC, option)
        outputs = """
  SyncFunctionArn:
    Value: !GetAtt CFirmarFunction.Arn
"""
        code_files = {"firmar.py": SYNC}
    text = doc(
        f"Lambdas de {LABEL[letter]} — Graviton, fuera de la VPC salvo CloudHSM, codigo embebido.",
        ARCH[letter],
        ["Handler index.handler porque ZipFile se publica como index.py", "Log group con retencion de 30 dias creado antes que la funcion"],
    ) + f"""
{params}{conditions}
Resources:
{resources}
Outputs:
{outputs}
"""
    return text, code_files


def lambda_fn(name, role_ref, timeout, memory, code, option):
    letter = option[-1]
    suffix = {"APresign": "a-presign", "AFirmar": "a-firmar", "BLote": "b-lote", "CFirmar": "c-firmar"}[name]
    extra_env = ""
    if name in ("BLote", "CFirmar"):
        extra_env = "\n          QUEUE_URL: !Ref QueueUrl"
    reserved = ""
    if name == "BLote":
        reserved = "\n      ReservedConcurrentExecutions: 1"
    vpc = """
      VpcConfig: !If
        - UseHsm
        - SecurityGroupIds:
            - !Ref LambdaSecurityGroupId
          SubnetIds:
            - !Ref SubnetA
            - !Ref SubnetB
        - !Ref AWS::NoValue"""
    why = {
        "APresign": "Entrega una URL de PUT de 15 minutos. No firma.",
        "AFirmar": "Consume SQS, firma el hash y escribe firmados. Devuelve fallos parciales.",
        "BLote": "Lista hasta 20 PDF por ciclo. Scheduler y API usan la misma funcion.",
        "CFirmar": "Firma dentro del limite de 29 segundos de API Gateway.",
    }[name]
    return f"""
  {name}LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/${{ProjectName}}-${{Environment}}-{suffix}
      RetentionInDays: 30
  {name}Function:
    Type: AWS::Lambda::Function
    DependsOn: {name}LogGroup
{rmeta(why, ["arm64", "ZipFile bajo 4 KB", "VpcConfig solo con DeployCloudHsm=true"])}
    Properties:
      FunctionName: !Sub ${{ProjectName}}-${{Environment}}-{suffix}
      Role: !Ref {role_ref}
      Runtime: python3.12
      Architectures:
        - arm64
      Handler: index.handler
      Timeout: {timeout}
      MemorySize: {memory}{reserved}
      Code:
{zip_block(code, 8)}
      Environment:
        Variables:
          BUCKET: !Ref BucketName
          UNSIGNED_PREFIX: !Ref UnsignedPrefix
          SIGNED_PREFIX: !Ref SignedPrefix
          KMS_KEY_ID: !Ref KeyArn
          CORS_ORIGIN: !Ref CorsAllowedOrigin{extra_env}{vpc}
      Tags:
{tags(LABEL[letter], 8)}
"""


def api(option):
    letter = option[-1]
    paths = {"a": ("documentos", "carga"), "b": ("lotes", "procesar"), "c": ("documentos", "firmar")}
    parent, leaf = paths[letter]
    binary = ""
    if letter == "c":
        binary = """
      BinaryMediaTypes:
        - application/pdf
        - application/octet-stream
"""
    methods = "'POST,OPTIONS'"
    return doc(
        f"API de {LABEL[letter]} — autorizacion AWS_IAM y stage igual al entorno.",
        ARCH[letter],
        ["AuthorizationType AWS_IAM en POST", "OPTIONS sin autenticacion solo para CORS", "Sin access log de API Gateway para no exigir el rol de cuenta"],
    ) + f"""
{common_params()}
  FunctionArn:
    Type: String
    Description: ARN de la Lambda que integra el POST.
  CorsAllowedOrigin:
    Type: String
    Description: Valor de Access-Control-Allow-Origin.
  ApiRevision:
    Type: String
    Default: "1"
    Description: Cambiar este valor fuerza un deployment nuevo.
Resources:
  RestApi:
    Type: AWS::ApiGateway::RestApi
{rmeta("Frente de la opcion. El PDF de la via sincrona entra como binario.", ["Endpoint REGIONAL", "AWS_IAM en el POST"])}
    Properties:
      Name: !Sub ${{ProjectName}}-${{Environment}}-{LABEL[letter]}
      EndpointConfiguration:
        Types:
          - REGIONAL
{binary}
      Tags:
{tags(LABEL[letter], 8)}
  ParentResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: {parent}
  LeafResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !Ref ParentResource
      PathPart: {leaf}
  PostMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref LeafResource
      HttpMethod: POST
      AuthorizationType: AWS_IAM
      Integration:
        Type: AWS_PROXY
        IntegrationHttpMethod: POST
        Uri: !Sub arn:aws:apigateway:${{AWS::Region}}:lambda:path/2015-03-31/functions/${{FunctionArn}}/invocations
  OptionsMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref LeafResource
      HttpMethod: OPTIONS
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{{"statusCode": 200}}'
        IntegrationResponses:
          - StatusCode: "200"
            ResponseParameters:
              method.response.header.Access-Control-Allow-Headers: "'Content-Type,Authorization,X-Amz-Date,X-Api-Key'"
              method.response.header.Access-Control-Allow-Methods: "{methods}"
              method.response.header.Access-Control-Allow-Origin: !Sub "'${{CorsAllowedOrigin}}'"
      MethodResponses:
        - StatusCode: "200"
          ResponseParameters:
            method.response.header.Access-Control-Allow-Headers: true
            method.response.header.Access-Control-Allow-Methods: true
            method.response.header.Access-Control-Allow-Origin: true
  InvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref FunctionArn
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub arn:aws:execute-api:${{AWS::Region}}:${{AWS::AccountId}}:${{RestApi}}/${{Environment}}/POST/{parent}/{leaf}
  Deployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn:
      - PostMethod
      - OptionsMethod
    Properties:
      RestApiId: !Ref RestApi
      Description: !Ref ApiRevision
  Stage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref Deployment
      StageName: !Ref Environment
      MethodSettings:
        - ResourcePath: "/*"
          HttpMethod: "*"
          ThrottlingBurstLimit: 20
          ThrottlingRateLimit: 10
      Tags:
{tags(LABEL[letter], 8)}
Outputs:
  ApiId:
    Value: !Ref RestApi
  ApiUrl:
    Value: !Sub https://${{RestApi}}.execute-api.${{AWS::Region}}.amazonaws.com/${{Environment}}/{parent}/{leaf}
"""


def cloudhsm(option):
    letter = option[-1]
    return doc(
        f"CloudHSM de {LABEL[letter]} — el cluster y dos HSM solo se crean con DeployCloudHsm=true.",
        ARCH[letter],
        ["Por defecto no hay HSM y no hay cargo por hora", "Si se activa, son dos hsm2m.medium en dos zonas", "Retain: borrar el stack no debe destruir el HSM sin una decision aparte"],
    ) + f"""
{common_params()}{HSM_PARAM}
  SubnetA:
    Type: String
    Description: Primera subred del cluster.
  SubnetB:
    Type: String
    Description: Segunda subred del cluster.
  AzA:
    Type: String
    Description: Zona de la primera subred.
  AzB:
    Type: String
    Description: Zona de la segunda subred.
Conditions:
  UseHsm: !Equals [!Ref DeployCloudHsm, "true"]
Resources:
  ModeMarker:
    Type: AWS::SSM::Parameter
{rmeta("Marca el modo de custodia aunque el cluster no exista. El stack anidado no puede quedar vacio.", ["El valor sigue a DeployCloudHsm"])}
    Properties:
      Name: !Sub /${{ProjectName}}/${{Environment}}/{LABEL[letter]}/cloudhsm
      Type: String
      Value: !Ref DeployCloudHsm
      Description: true solo si este stack creo el cluster
  Cluster:
    Type: AWS::CloudHSMV2::Cluster
    Condition: UseHsm
{rmeta("Custodia dedicada. La Lambda actual sigue firmando con KMS; el HSM queda listo para un cliente PKCS#11.", ["hsm2m.medium", "Dos subredes", "No crear si DeployCloudHsm es false"])}
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      HsmType: hsm2m.medium
      SubnetIds:
        - !Ref SubnetA
        - !Ref SubnetB
      BackupRetentionPolicy:
        Type: DAYS
        Value: "7"
      Tags:
{tags(LABEL[letter], 8)}
  HsmA:
    Type: AWS::CloudHSMV2::HSM
    Condition: UseHsm
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ClusterId: !Ref Cluster
      AvailabilityZone: !Ref AzA
  HsmB:
    Type: AWS::CloudHSMV2::HSM
    Condition: UseHsm
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ClusterId: !Ref Cluster
      AvailabilityZone: !Ref AzB
Outputs:
  CloudHsmMode:
    Value: !Ref DeployCloudHsm
  ClusterId:
    Condition: UseHsm
    Value: !Ref Cluster
"""


def main_template(option):
    letter = option[-1]
    b_params = ""
    b_pass_s3 = ""
    b_pass_lambda = ""
    if letter == "b":
        b_params = """
  SourceLocationArn:
    Type: String
    Default: ""
    Description: ARN DataSync del origen. Vacio no crea la tarea.
  DataSyncSchedule:
    Type: String
    Default: cron(0 * * * ? *)
    Description: Agenda de copia DataSync.
  ProcessSchedule:
    Type: String
    Default: rate(15 minutes)
    Description: Agenda de la Lambda de lote.
"""
        b_pass_s3 = """
        SourceLocationArn: !Ref SourceLocationArn
        DataSyncSchedule: !Ref DataSyncSchedule
"""
        b_pass_lambda = """
        ProcessSchedule: !Ref ProcessSchedule
        SchedulerRoleArn: !GetAtt IamStack.Outputs.SchedulerRoleArn
        QueueUrl: !GetAtt SqsStack.Outputs.QueueUrl
"""
    iam_pass = {
        "a": """
        PresignRoleArn: !GetAtt IamStack.Outputs.PresignRoleArn
        SignerRoleArn: !GetAtt IamStack.Outputs.SignerRoleArn
        QueueArn: !GetAtt SqsStack.Outputs.QueueArn
""",
        "b": """
        LoteRoleArn: !GetAtt IamStack.Outputs.LoteRoleArn
""",
        "c": """
        SyncRoleArn: !GetAtt IamStack.Outputs.SyncRoleArn
        QueueUrl: !GetAtt SqsStack.Outputs.QueueUrl
""",
    }[letter]
    if letter == "a":
        lambda_queue = "        QueueArn: !GetAtt SqsStack.Outputs.QueueArn\n"
        fn_out = "PresignFunctionArn"
        s3_queue = "        QueueArn: !GetAtt SqsStack.Outputs.QueueArn\n"
    elif letter == "b":
        lambda_queue = "        QueueArn: !GetAtt SqsStack.Outputs.QueueArn\n" + b_pass_lambda
        fn_out = "LoteFunctionArn"
        s3_queue = b_pass_s3
    else:
        lambda_queue = ""
        fn_out = "SyncFunctionArn"
        s3_queue = ""
    # iam_pass for A already includes QueueArn, so lambda_queue would duplicate for A.
    # I included QueueArn in iam_pass for A AND lambda_queue. Fix: iam_pass is roles,
    # lambda_queue is queue. Let me rebuild iam_pass to be only roles.
    return "PLACEHOLDER"


def main_template(option):
    letter = option[-1]
    extra_params = ""
    s3_extra = ""
    lambda_extra = ""
    if letter == "a":
        s3_extra = "        QueueArn: !GetAtt SqsStack.Outputs.QueueArn\n"
        lambda_extra = """        QueueArn: !GetAtt SqsStack.Outputs.QueueArn
        PresignRoleArn: !GetAtt IamStack.Outputs.PresignRoleArn
        SignerRoleArn: !GetAtt IamStack.Outputs.SignerRoleArn
"""
        fn = "PresignFunctionArn"
    elif letter == "b":
        extra_params = """
  SourceLocationArn:
    Type: String
    Default: ""
    Description: ARN DataSync del origen. Vacio no crea la tarea.
  DataSyncSchedule:
    Type: String
    Default: cron(0 * * * ? *)
    Description: Agenda de copia DataSync.
  ProcessSchedule:
    Type: String
    Default: rate(15 minutes)
    Description: Agenda de la Lambda de lote.
"""
        s3_extra = """        SourceLocationArn: !Ref SourceLocationArn
        DataSyncSchedule: !Ref DataSyncSchedule
"""
        lambda_extra = """        QueueArn: !GetAtt SqsStack.Outputs.QueueArn
        QueueUrl: !GetAtt SqsStack.Outputs.QueueUrl
        LoteRoleArn: !GetAtt IamStack.Outputs.LoteRoleArn
        SchedulerRoleArn: !GetAtt IamStack.Outputs.SchedulerRoleArn
        ProcessSchedule: !Ref ProcessSchedule
"""
        fn = "LoteFunctionArn"
    else:
        lambda_extra = """        QueueUrl: !GetAtt SqsStack.Outputs.QueueUrl
        SyncRoleArn: !GetAtt IamStack.Outputs.SyncRoleArn
"""
        fn = "SyncFunctionArn"
    return doc(
        f"Stack raiz de {LABEL[letter]} — anida red, llave, bucket, roles, Lambdas y API. CloudHSM queda apagado.",
        ARCH[letter],
        ["TemplatesBaseUrl apunta a esta carpeta en S3, sin barra final", "DeployCloudHsm por defecto false"],
    ) + f"""
Parameters:
  TemplatesBaseUrl:
    Type: String
    AllowedPattern: "^https://.+"
    ConstraintDescription: URL https del prefijo de las plantillas, sin barra final.
    Description: Prefijo HTTPS donde se publicaron los templates anidados. Sin barra final.
{PARAMS}{HSM_PARAM}{PREFIX_PARAMS}
  ApiRevision:
    Type: String
    Default: "1"
    Description: Subir este valor publica de nuevo el stage.
{extra_params}
Resources:
  VpcStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/vpc/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
        DeployCloudHsm: !Ref DeployCloudHsm
  KmsStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/kms/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
  SqsStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/sqs/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
  S3Stack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/s3/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
        UnsignedPrefix: !Ref UnsignedPrefix
        SignedPrefix: !Ref SignedPrefix
        CorsAllowedOrigin: !Ref CorsAllowedOrigin
{s3_extra}
  IamStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/iam/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
        UnsignedPrefix: !Ref UnsignedPrefix
        SignedPrefix: !Ref SignedPrefix
        CorsAllowedOrigin: !Ref CorsAllowedOrigin
        BucketArn: !GetAtt S3Stack.Outputs.BucketArn
        KeyArn: !GetAtt KmsStack.Outputs.KeyArn
        QueueArn: !GetAtt SqsStack.Outputs.QueueArn
  LambdaStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/lambda/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
        DeployCloudHsm: !Ref DeployCloudHsm
        UnsignedPrefix: !Ref UnsignedPrefix
        SignedPrefix: !Ref SignedPrefix
        CorsAllowedOrigin: !Ref CorsAllowedOrigin
        BucketName: !GetAtt S3Stack.Outputs.BucketName
        KeyArn: !GetAtt KmsStack.Outputs.KeyArn
        SubnetA: !GetAtt VpcStack.Outputs.SubnetA
        SubnetB: !GetAtt VpcStack.Outputs.SubnetB
        LambdaSecurityGroupId: !GetAtt VpcStack.Outputs.LambdaSecurityGroupId
{lambda_extra}
  ApiStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/apigateway/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
        CorsAllowedOrigin: !Ref CorsAllowedOrigin
        ApiRevision: !Ref ApiRevision
        FunctionArn: !GetAtt LambdaStack.Outputs.{fn}
  CloudHsmStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub ${{TemplatesBaseUrl}}/cloudhsm/tamplate.yaml
      Parameters:
        ProjectName: !Ref ProjectName
        Environment: !Ref Environment
        DeployCloudHsm: !Ref DeployCloudHsm
        SubnetA: !GetAtt VpcStack.Outputs.SubnetA
        SubnetB: !GetAtt VpcStack.Outputs.SubnetB
        AzA: !GetAtt VpcStack.Outputs.AzA
        AzB: !GetAtt VpcStack.Outputs.AzB
Outputs:
  BucketName:
    Value: !GetAtt S3Stack.Outputs.BucketName
  KeyArn:
    Value: !GetAtt KmsStack.Outputs.KeyArn
  ApiUrl:
    Value: !GetAtt ApiStack.Outputs.ApiUrl
  CloudHsmMode:
    Value: !GetAtt CloudHsmStack.Outputs.CloudHsmMode
"""


def vars_file(option):
    letter = option[-1]
    extra = ""
    if letter == "b":
        extra = """
SourceLocationArn: ""
DataSyncSchedule: cron(0 * * * ? *)
ProcessSchedule: rate(15 minutes)
"""
    return f"""# Parametros de {LABEL[letter]}. No es una plantilla.
# 1. Publicar esta carpeta:
#    aws s3 sync opcion_{letter} s3://NOMBRE-BUCKET/opcion_{letter} --exclude "*" --include "*.yaml"
# 2. Desplegar el stack raiz (el archivo local; los hijos salen de S3):
#    aws cloudformation deploy \\
#      --template-file opcion_{letter}/template_main.yaml \\
#      --stack-name firma-{LABEL[letter]} \\
#      --capabilities CAPABILITY_IAM \\
#      --parameter-overrides \\
#        TemplatesBaseUrl=https://NOMBRE-BUCKET.s3.${{AWS::Region}}.amazonaws.com/opcion_{letter} \\
#        ProjectName=firma-digital Environment=dev DeployCloudHsm=false \\
#        CorsAllowedOrigin=https://localhost ApiRevision=1
# DeployCloudHsm=true crea dos HSM y empieza el cargo por hora.
TemplatesBaseUrl: https://NOMBRE-BUCKET.s3.REGION.amazonaws.com/opcion_{letter}
ProjectName: firma-digital
Environment: dev
DeployCloudHsm: "false"
CorsAllowedOrigin: https://localhost
UnsignedPrefix: sin-firmar/
SignedPrefix: firmados/
ApiRevision: "1"
{extra}"""


def main():
    for name, code in {
        "presign": PRESIGN,
        "worker": WORKER,
        "lote": LOTE,
        "sync": SYNC,
    }.items():
        assert_zip(name, code)
        compile(code, name + ".py", "exec")
    for letter in ("a", "b", "c"):
        option = f"opcion_{letter}"
        base = ROOT / option
        write(base / "vpc" / "tamplate.yaml", vpc(option))
        write(base / "kms" / "tamplate.yaml", kms(option))
        write(base / "sqs" / "tamplate.yaml", sqs(option))
        write(base / "s3" / "tamplate.yaml", s3(option))
        write(base / "iam" / "tamplate.yaml", iam(option))
        lambda_text, sources = lambdas(option)
        write(base / "lambda" / "tamplate.yaml", lambda_text)
        for filename, source in sources.items():
            write(base / "lambda" / "src" / filename, source)
        write(base / "apigateway" / "tamplate.yaml", api(option))
        write(base / "cloudhsm" / "tamplate.yaml", cloudhsm(option))
        write(base / "template_main.yaml", main_template(option))
        write(base / "vars.yaml", vars_file(option))
        print("wrote", option)


if __name__ == "__main__":
    main()
