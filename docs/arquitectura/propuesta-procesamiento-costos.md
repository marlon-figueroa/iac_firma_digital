# Procesamiento y costos
## Autor: Marlon E. Figueroa
Infraestructura como código | Firma digital de documentos

Dos vías de carga, un bucket y un acceso síncrono.

Propuesta para firmar documentos con el mismo bucket, carpetas sin-firmar y firmados, y tres formas de entrar: carga con URL prefirmada, depósito por DataSync y un endpoint síncrono. Los importes son precios de lista de us-east-1 al 30 de septiembre de 2026. Cada escenario supone que todo el volumen entra por un solo canal.

> **Propuesta base: firmar con KMS.** A 10.000 documentos al mes, la vía de URL prefirmada con una llave ECC P-256 en KMS cuesta $10.63. La misma vía con un clúster de dos HSM hsm2m.medium cuesta $2,375.61. El canal mueve el total en dólares. La custodia de la llave de firma lo mueve en miles. CloudHSM entra cuando esa llave tiene que residir en un HSM dedicado FIPS 140-3 Level 3. Un custom key store de KMS sobre CloudHSM solo admite llaves AES simétricas y no reemplaza la firma del PDF. El cifrado en reposo, en los dos casos, usa llaves de KMS de administración del cliente.

## 1. Cómo se procesa cada documento

Las dos vías escriben en los mismos prefijos. La síncrona es un tercer acceso para quien necesita la respuesta en la misma llamada. Una librería PAdES en la Lambda arma el PKCS#7. KMS o CloudHSM firman el hash. El PDF, la cola y los logs se cifran aparte, con llaves simétricas de KMS de la cuenta.

### Carpetas

`s3://firma-documentos/sin-firmar/` recibe el PDF original. `s3://firma-documentos/firmados/` guarda el PDF con la firma embebida. Un lifecycle borra sin-firmar a los 7 días. La identidad que firma es la única con `kms:Sign` o con el usuario criptográfico del HSM. La Lambda que emite la URL solo puede hacer `PutObject` sobre `sin-firmar/`.

### Cifrado en reposo

Cada almacén usa su propia llave de KMS, creada y administrada en la cuenta. No se usa SSE-S3 ni una llave administrada por AWS, como `aws/s3`, `aws/sqs` o `aws/logs`. El bucket cifra con SSE-KMS y una llave simétrica del cliente. La política del bucket niega el `PutObject` si el algoritmo no es `aws:kms` o si la llave no es esa. La URL prefirmada incluye esos encabezados, así el cliente no puede subir el PDF en claro ni con SSE-S3.

La cola y su DLQ comparten otra llave simétrica de cliente. El log group de CloudWatch usa una tercera. La llave de firma sigue siendo ECC P-256 y no cifra objetos: KMS no acepta una llave asimétrica como llave de SSE-KMS. Con CloudHSM la firma sale del clúster, pero S3, SQS y los logs siguen cifrados con estas llaves de cliente.

### Opción A. URL prefirmada y SQS

El portal llama a API Gateway. Una Lambda breve devuelve una URL prefirmada de PUT, válida 15 minutos, sobre `sin-firmar/{id}.pdf`. El cliente sube el archivo directo a S3. El evento ObjectCreated de ese prefijo entra a SQS. La Lambda firmadora lee el objeto, firma el hash y escribe `firmados/{id}.pdf`. Si la firma falla, el mensaje vuelve a la cola y, agotados los reintentos, queda en una DLQ. La latencia habitual es de segundos. El PDF no pasa por API Gateway, así que el tamaño sigue el límite de S3.

### Opción B. DataSync y EventBridge

Un agente de DataSync en el origen copia el lote al mismo prefijo `sin-firmar/`. EventBridge Scheduler despierta la Lambda de lote cada 15 minutos. Esa Lambda lista lo pendiente, firma cada PDF y lo escribe en `firmados/`. Lo que no alcance a procesar en un ciclo queda para el siguiente. La latencia es la ventana de 15 minutos. Las invocaciones del scheduler entran en el free tier de 14 millones al mes, así que el schedule en sí no suma costo.

### Acceso síncrono, común a las dos vías

`POST /documentos/firmar` acepta el PDF, hasta 10 MB, o la clave de un objeto ya subido. La misma Lambda firma y responde con la clave en `firmados/`. API Gateway cierra la llamada a los 29 segundos. Un archivo más grande, o un depósito de DataSync, sigue por la opción A o la B. La respuesta es un JSON con la clave del objeto firmado, no el PDF, para no pagar salida de datos.

### Custodia de la llave de firma

Con KMS, la Lambda llama a `Sign` con una llave ECC P-256 (`ECDSA_SHA_256`). La llave no sale de KMS. Si los verificadores exigen RSA, la misma arquitectura usa `RSA_2048`. Con CloudHSM, la Lambda en la VPC, o una tarea junto al clúster, usa el SDK PKCS#11 o JCE y firma el mismo hash. El custom key store no cubre llaves asimétricas. Por defecto, CloudHSM se mantiene «apagado» (ver sección 3).

## 2. Costo mensual con la llave de firma en KMS

Costo de lista de un mes de 730 horas, sin free tier, con el PDF firmado retenido 12 meses en S3 Standard. A 10.000 documentos las tres vías quedan entre $9.65 y $10.63. El salto frente a un cifrado SSE-S3 es el de las llaves de cliente y sus solicitudes, no el del canal.

| Documentos al mes | A. Prefirmada | B. DataSync | Síncrono |
| --- | ---: | ---: | ---: |
| 1.000 | $4.67 | $3.68 | $3.70 |
| 10.000 | $10.63 | $9.65 | $9.93 |
| 100.000 | $69.78 | $69.32 | $72.19 |
| 1.000.000 | $661.37 | $666.05 | $694.86 |

Eje de la tabla: documentos procesados en el mes y USD de lista. Incluye almacenamiento y el cifrado con llaves de cliente. A 1 millón de documentos, $549.54 de los $661.37 de la opción A son S3.

### Desglose a 10.000 documentos, firma con KMS

| Concepto | A. Prefirmada | B. DataSync | Síncrono |
| --- | ---: | ---: | ---: |
| API Gateway | $0.04 | $0.00 | $0.04 |
| Lambda | $0.68 | $0.55 | $1.07 |
| S3 solicitudes | $0.10 | $0.11 | $0.10 |
| S3 almacenamiento | $5.50 | $5.50 | $5.50 |
| SQS | $0.01 | $0.00 | $0.00 |
| DataSync | $0.00 | $0.24 | $0.00 |
| KMS llaves de cliente | $4.00 | $3.00 | $3.00 |
| KMS firmas ECC P-256 | $0.15 | $0.15 | $0.15 |
| KMS cifrado S3 | $0.09 | $0.09 | $0.06 |
| KMS cifrado SQS | $0.05 | $0.00 | $0.00 |
| CloudWatch Logs | $0.01 | $0.01 | $0.01 |
| Total mensual | $10.63 | $9.65 | $9.93 |

La opción A paga cuatro llaves de cliente, a $1 cada una: firma ECC, bucket, cola y logs. B y la síncrona pagan tres, porque no hay cola. De los $5.50 de almacenamiento, $5.39 son firmados retenidos 12 meses y $0.10 es sin-firmar durante 7 días. Si firmados pasa a S3 Standard-IA a los 90 días, el almacenamiento de este volumen baja a $3.75.

## 3. CloudHSM: costo y modo «apagado»

### ¿Qué significa «CloudHSM apagado»?

En AWS CloudHSM no existe un botón de «pausa» o «detener» como en EC2 o RDS. Un HSM aprovisionado es una tarjeta física dedicada (módulo criptográfico FIPS 140-3 Nivel 3) que AWS factura ininterrumpidamente a **$1.60 USD por hora** por cada HSM activo ($2,336 USD al mes por dos HSM en alta disponibilidad), haya o no firmas en curso.

En esta arquitectura y en sus plantillas de CloudFormation, **«CloudHSM apagado» significa que el parámetro `DeployCloudHsm` tiene valor `false` (valor por defecto)**. Este estado implica:

- **Cero recursos de hardware aprovisionados:** La condición `UseHsm` omite la creación del clúster `AWS::CloudHSMV2::Cluster` y de los dos HSMs. El costo de hardware es de **$0.00 USD al mes**.
- **Lambdas fuera de la VPC:** Las funciones Lambda corren de forma nativa sin asociarse a subredes privadas, ahorrando los VPC Endpoints privados de interfaz ($29.20 USD al mes) y eliminando sobrecargas de red.
- **Firma digital 100% operativa en KMS:** La firma se realiza con una llave asimétrica ECC NIST P-256 en **AWS KMS**. El costo base es de apenas **$1.00 USD al mes** por la llave y **$0.15 USD** por cada 10.000 firmas, ofreciendo alta seguridad FIPS 140-2/3 Nivel 3 multi-inquilino.

### Cómo se apaga y reanuda un clúster en AWS

En una cuenta de AWS real, para dejar de pagar por CloudHSM sin perder certificados ni claves criptográficas, el procedimiento operativo consiste en:

1. **Copia de seguridad (Backup):** Tomar un Backup del clúster (las llaves se cifran y quedan respaldadas en S3 gestionado por el servicio).
2. **Eliminar instancias HSM (`DeleteHsm`):** Al quedar con 0 HSMs activos, el cobro por hora pasa a **$0 USD**.
3. **Reanudación (`CreateHsm`):** Para «encenderlo» de nuevo, se crean las instancias HSM a partir de la copia de seguridad guardada.

### Impacto de activar el modo encendido (`DeployCloudHsm: true`)

Al cambiar `DeployCloudHsm` a `true`:

- Se aprovisionan dos HSM `hsm2m.medium` en dos zonas de disponibilidad distintas dentro de la VPC.
- Las Lambdas se adjuntan a las subredes privadas (`VpcConfig`) para comunicarse mediante cliente PKCS#11 o JCE con las IPs privadas del clúster.
- Se crean VPC Interface Endpoints para alcanzar SQS, S3 y CloudWatch Logs sin NAT Gateway ni salida a internet.
- El costo base mensual asciende a **$2,375.61 USD** (a 10.000 documentos), justificable cuando normativas bancarias o de auditoría exigen hardware monoinquilino dedicado.

### Costo mensual con clúster activo (dos HSM hsm2m.medium)

Dos HSM `hsm2m.medium` encendidos el mes completo (730 h) suman $2,336 más $29.20 de endpoints de interfaz. La firma PKCS#11 no paga el Sign de KMS. S3, la cola y los logs sí continúan pagando sus llaves de cliente. La Lambda firmadora va en la VPC: 1,5 GB y 8 segundos en la opción A, frente a 1 GB y 5 segundos con KMS.

| Documentos al mes | A. Prefirmada | B. DataSync | Síncrono |
| --- | ---: | ---: | ---: |
| 1.000 | $2,368.94 | $2,367.93 | $2,367.97 |
| 10.000 | $2,375.61 | $2,374.37 | $2,374.91 |
| 100.000 | $2,441.82 | $2,438.69 | $2,444.22 |
| 1.000.000 | $3,103.91 | $3,081.92 | $3,137.39 |

Hasta 100.000 documentos al mes el clúster es casi todo el recibo. A 1 millón, el almacenamiento de 12 meses ($549.54) ya se nota al lado de los $2,336 del HSM. En desarrollo conviene siempre firmar con KMS manteniendo CloudHSM apagado.

## 4. Qué canal conviene

| Criterio | A. Prefirmada y SQS | B. DataSync | Síncrono |
| --- | --- | --- | --- |
| Origen | Portal o aplicación | File share, NAS u otro sistema | Aplicación que espera el resultado |
| Latencia | Segundos | Hasta 15 minutos | La de la llamada, tope 29 s |
| Tamaño | El límite de PUT en S3 | El del lote | Hasta 10 MB |
| Disparador | S3 hacia SQS | Schedule cada 15 min | POST /documentos/firmar |
| Reintento | SQS y DLQ | El ciclo siguiente | El cliente reintenta |

Las tres pueden convivir. Las llaves de cliente se pagan una vez: $4 si están las tres vías (firma, bucket, cola y logs) y $3 si no hay SQS. Con CloudHSM no se crea la llave de firma, y el fijo de cifrado queda en $3 o $2, además de $2,336 del clúster y $29.20 de endpoints. El variable se prorratea según cuántos documentos entren por cada canal.

## 5. Supuestos

Región us-east-1. PDF medio de 2 MiB. Lambda en Graviton, a $0.0000133334 por GB-segundo y $0.20 por millón de invocaciones. La prefirmada usa 256 MB y 200 ms. La firmadora de la opción A usa 1 GB y 5 s con KMS. El lote usa 4 s por documento con KMS. La síncrona usa 8 s con KMS. API Gateway REST a $3.50 por millón. DataSync Basic a $0.0125 por GB, con agente on-premises. S3 Standard a $0.023 por GB-mes; PUT a $0.005 por 1.000; GET a $0.0004 por 1.000. SQS estándar, tres solicitudes por documento, a $0.40 por millón. Logs, 2 KiB por documento a $0.50 por GB.

Cifrado en reposo siempre con llaves de KMS de administración del cliente, una por almacén, a $1 al mes. El bucket usa SSE-KMS con su llave simétrica. No usa SSE-S3 ni la llave aws/s3. La cola no usa el cifrado administrado por SQS. Los logs no usan la llave aws/logs. Las solicitudes simétricas se cobran a $0.03 por 10.000 y este documento no resta las 20.000 gratuitas. S3 cuenta 3 solicitudes por documento en A y B (PUT del original, GET para firmar y PUT del firmado) y 2 en la síncrona, que no relee el objeto. La cola reutiliza la data key durante 5 minutos. Con llegada uniforme en las 730 horas, son dos llamadas KMS por ventana de 5 minutos a partir de unos 8.800 documentos al mes, y dos por documento por debajo de ese ritmo.

Activar S3 Bucket Key no cambia de llave: la data key de bucket sale de la misma llave de cliente y puede bajar el renglón de cifrado de S3 hasta un 99%. Ese ahorro no está en los totales. El free tier permanente de Lambda (1 millón de invocaciones y 400.000 GB-segundo) cubre del orden de 79.000 documentos al mes en la opción A con KMS. Por debajo de ese volumen el cómputo real se acerca a las llaves de cliente más el almacenamiento. Las firmas asimétricas de KMS quedan fuera de ese free tier. RSA 2048 se cobra a $0.03 por 10.000 solicitudes, una quinta parte del renglón de firmas ECC de este documento.

Quedan fuera del total: un clúster de desarrollo, tráfico entre regiones, WAF, y el modo aprovisionado del event source mapping de SQS. Ese modo se cobra por Event Poller Unit-hora; el ejemplo oficial de SQS usa $0.00925. El polling estándar de SQS, que es el de esta propuesta, no lleva ese cargo. Si el agente de DataSync corre en EC2 en lugar de on-premises, hay que sumar esa instancia. Reemplazar la Lambda firmadora de CloudHSM por una tarea Fargate encendida todo el mes suma decenas de dólares y no cambia la decisión de custodia.

## 6. Fuentes de precio

CloudHSM hsm2m.medium a $1.60 por hora: ejemplo oficial de la página de precios de AWS KMS para un clúster de 2 HSM en US East (N. Virginia). KMS: $1 por llave de cliente al mes, sea simétrica o asimétrica; $0.03 por 10.000 solicitudes simétricas; $0.15 por 10.000 firmas ECC, ejemplo de file signing de la misma página. RSA 2048 a $0.03 por 10.000, tarifa publicada de KMS. Lambda ARM a $0.0000133334 por GB-segundo y $0.20 por millón de solicitudes, página de precios de Lambda. API Gateway REST a $3.50 por millón, ejemplo oficial de US East. DataSync Basic a $0.0125 por GB, página de precios de DataSync. S3 Standard a $0.023 por GB-mes, PUT $0.005 / 1.000 y GET $0.0004 / 1.000, lista de us-east-1. SQS estándar a $0.40 por millón después del primer millón. VPC interface endpoint a $0.01 por hora por zona.

Precios de lista AWS. Sin free tier. PDF de 2 MiB.
