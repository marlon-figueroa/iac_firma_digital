# Procesamiento y costos
## Autor: Marlon E. Figueroa
Infraestructura como código | Firma digital de documentos

Dos vías de carga, un bucket y un acceso síncrono.

Propuesta para firmar documentos con el mismo bucket, carpetas sin-firmar y firmados, y tres formas de entrar: carga con URL prefirmada, depósito por DataSync y un endpoint síncrono. Los importes son precios de lista de us-east-1 al 30 de septiembre de 2026. Cada escenario supone que todo el volumen entra por un solo canal.

> **Propuesta base: firmar con KMS.** A 10.000 documentos al mes, la vía de URL prefirmada con una llave ECC P-256 en KMS cuesta $7.48. La misma vía con un clúster de dos HSM hsm2m.medium cuesta $2,372.47. El canal mueve el total en dólares. La custodia de la llave lo mueve en miles. CloudHSM entra cuando la llave tiene que residir en un HSM dedicado FIPS 140-3 Level 3. Un custom key store de KMS sobre CloudHSM solo admite llaves AES simétricas y no reemplaza la firma del PDF.

## 1. Cómo se procesa cada documento

Las dos vías escriben en los mismos prefijos. La síncrona es un tercer acceso para quien necesita la respuesta en la misma llamada. Una librería PAdES en la Lambda arma el PKCS#7. KMS o CloudHSM solo firman el hash.

### Carpetas

`s3://firma-documentos/sin-firmar/` recibe el PDF original. `s3://firma-documentos/firmados/` guarda el PDF con la firma embebida. Un lifecycle borra sin-firmar a los 7 días. La identidad que firma es la única con `kms:Sign` o con el usuario criptográfico del HSM. La Lambda que emite la URL solo puede hacer `PutObject` sobre `sin-firmar/`.

### Opción A. URL prefirmada y SQS

El portal llama a API Gateway. Una Lambda breve devuelve una URL prefirmada de PUT, válida 15 minutos, sobre `sin-firmar/{id}.pdf`. El cliente sube el archivo directo a S3. El evento ObjectCreated de ese prefijo entra a SQS. La Lambda firmadora lee el objeto, firma el hash y escribe `firmados/{id}.pdf`. Si la firma falla, el mensaje vuelve a la cola y, agotados los reintentos, queda en una DLQ. La latencia habitual es de segundos. El PDF no pasa por API Gateway, así que el tamaño sigue el límite de S3.

### Opción B. DataSync y EventBridge

Un agente de DataSync en el origen copia el lote al mismo prefijo `sin-firmar/`. EventBridge Scheduler despierta la Lambda de lote cada 15 minutos. Esa Lambda lista lo pendiente, firma cada PDF y lo escribe en `firmados/`. Lo que no alcance a procesar en un ciclo queda para el siguiente. La latencia es la ventana de 15 minutos. Las invocaciones del scheduler entran en el free tier de 14 millones al mes, así que el schedule en sí no suma costo.

### Acceso síncrono, común a las dos vías

`POST /documentos/firmar` acepta el PDF, hasta 10 MB, o la clave de un objeto ya subido. La misma Lambda firma y responde con la clave en `firmados/`. API Gateway cierra la llamada a los 29 segundos. Un archivo más grande, o un depósito de DataSync, sigue por la opción A o la B. La respuesta es un JSON con la clave del objeto firmado, no el PDF, para no pagar salida de datos.

### Custodia de la llave

Con KMS, la Lambda llama a `Sign` con una llave ECC P-256 (`ECDSA_SHA_256`). La llave no sale de KMS. Si los verificadores exigen RSA, la misma arquitectura usa `RSA_2048`. Con CloudHSM, la Lambda en la VPC, o una tarea junto al clúster, usa el SDK PKCS#11 o JCE y firma el mismo hash. El custom key store no cubre llaves asimétricas.

## 2. Costo mensual con la llave en KMS

Costo de lista de un mes de 730 horas, sin free tier, con el PDF firmado retenido 12 meses en S3 Standard. A 10.000 documentos las tres vías quedan entre $7.48 y $7.86.

| Documentos al mes | A. Prefirmada | B. DataSync | Síncrono |
| --- | ---: | ---: | ---: |
| 1.000 | $1.65 | $1.67 | $1.69 |
| 10.000 | $7.48 | $7.56 | $7.86 |
| 100.000 | $65.83 | $66.42 | $69.59 |
| 1.000.000 | $649.33 | $655.07 | $686.87 |

Eje de la tabla: documentos procesados en el mes y USD de lista. Incluye almacenamiento. A 1 millón de documentos, $549.54 de los $649.33 de la opción A son S3.

### Desglose a 10.000 documentos, solo KMS

| Concepto | A. Prefirmada | B. DataSync | Síncrono |
| --- | ---: | ---: | ---: |
| API Gateway | $0.04 | $0.00 | $0.04 |
| Lambda | $0.68 | $0.55 | $1.07 |
| S3 solicitudes | $0.10 | $0.11 | $0.10 |
| S3 almacenamiento | $5.50 | $5.50 | $5.50 |
| SQS | $0.01 | $0.00 | $0.00 |
| DataSync | $0.00 | $0.24 | $0.00 |
| KMS llave | $1.00 | $1.00 | $1.00 |
| KMS firmas ECC P-256 | $0.15 | $0.15 | $0.15 |
| CloudWatch Logs | $0.01 | $0.01 | $0.01 |
| Total mensual | $7.48 | $7.56 | $7.86 |

De esos $5.50 de almacenamiento, $5.39 son firmados retenidos 12 meses y $0.10 es sin-firmar durante 7 días. Si firmados pasa a S3 Standard-IA a los 90 días, el almacenamiento de este volumen baja a $3.75.

## 3. Costo mensual con CloudHSM

Dos HSM hsm2m.medium, encendidos el mes completo, cuestan $2,336 (2 x $1.60 x 730 h). El ejemplo oficial de AWS usa 31 días, 744 horas, y da $2,380.80. Sumar dos VPC endpoints (SQS y CloudWatch Logs) en dos zonas de disponibilidad agrega $29.20. La firma PKCS#11 no paga el Sign de KMS. La Lambda firmadora va en la VPC: 1,5 GB y 8 segundos en la opción A, frente a 1 GB y 5 segundos con KMS.

### USD al mes, clúster de 2 HSM

| Documentos al mes | A. Prefirmada | B. DataSync | Síncrono |
| --- | ---: | ---: | ---: |
| 1.000 | $2,365.93 | $2,365.93 | $2,365.96 |
| 10.000 | $2,372.47 | $2,372.28 | $2,372.84 |
| 100.000 | $2,437.87 | $2,435.79 | $2,441.62 |
| 1.000.000 | $3,091.87 | $3,070.93 | $3,129.40 |

Hasta 100.000 documentos al mes el clúster es casi todo el recibo. A 1 millón, el almacenamiento de 12 meses ($549.54) ya se nota al lado de los $2,336 del HSM. Un segundo clúster para desarrollo duplica esa cifra. En desarrollo conviene firmar con KMS.

## 4. Qué canal conviene

| Criterio | A. Prefirmada y SQS | B. DataSync | Síncrono |
| --- | --- | --- | --- |
| Origen | Portal o aplicación | File share, NAS u otro sistema | Aplicación que espera el resultado |
| Latencia | Segundos | Hasta 15 minutos | La de la llamada, tope 29 s |
| Tamaño | El límite de PUT en S3 | El del lote | Hasta 10 MB |
| Disparador | S3 hacia SQS | Schedule cada 15 min | POST /documentos/firmar |
| Reintento | SQS y DLQ | El ciclo siguiente | El cliente reintenta |

Las tres pueden convivir. El fijo de la llave KMS ($1) o del clúster CloudHSM ($2,336 más $29.20 de endpoints) se paga una vez. El variable se prorratea según cuántos documentos entren por cada canal.

## 5. Supuestos

Región us-east-1. PDF medio de 2 MiB. Lambda en Graviton, a $0.0000133334 por GB-segundo y $0.20 por millón de invocaciones. La prefirmada usa 256 MB y 200 ms. La firmadora de la opción A usa 1 GB y 5 s con KMS. El lote usa 4 s por documento con KMS. La síncrona usa 8 s con KMS. API Gateway REST a $3.50 por millón. DataSync Basic a $0.0125 por GB, con agente on-premises. S3 Standard a $0.023 por GB-mes; PUT a $0.005 por 1.000; GET a $0.0004 por 1.000. SQS estándar, tres solicitudes por documento, a $0.40 por millón. Logs, 2 KiB por documento a $0.50 por GB. Cifrado del bucket con SSE-S3.

El free tier permanente de Lambda (1 millón de invocaciones y 400.000 GB-segundo) cubre del orden de 79.000 documentos al mes en la opción A con KMS. Por debajo de ese volumen el cómputo real se acerca a la llave de $1 más el almacenamiento. Las firmas asimétricas de KMS quedan fuera de ese free tier. RSA 2048 se cobra a $0.03 por 10.000 solicitudes, una quinta parte del renglón de firmas ECC de este documento.

Quedan fuera del total: un clúster de desarrollo, tráfico entre regiones, WAF, y el modo aprovisionado del event source mapping de SQS. Ese modo se cobra por Event Poller Unit-hora; el ejemplo oficial de SQS usa $0.00925. El polling estándar de SQS, que es el de esta propuesta, no lleva ese cargo. Si el agente de DataSync corre en EC2 en lugar de on-premises, hay que sumar esa instancia. Reemplazar la Lambda firmadora de CloudHSM por una tarea Fargate encendida todo el mes suma decenas de dólares y no cambia la decisión de custodia.

## 6. Fuentes de precio

CloudHSM hsm2m.medium a $1.60 por hora: ejemplo oficial de la página de precios de AWS KMS para un clúster de 2 HSM en US East (N. Virginia). KMS: $1 por llave al mes y $0.15 por 10.000 firmas ECC, ejemplo de file signing de la misma página. RSA 2048 a $0.03 por 10.000, tarifa publicada de KMS. Lambda ARM a $0.0000133334 por GB-segundo y $0.20 por millón de solicitudes, página de precios de Lambda. API Gateway REST a $3.50 por millón, ejemplo oficial de US East. DataSync Basic a $0.0125 por GB, página de precios de DataSync. S3 Standard a $0.023 por GB-mes, PUT $0.005 / 1.000 y GET $0.0004 / 1.000, lista de us-east-1. SQS estándar a $0.40 por millón después del primer millón. VPC interface endpoint a $0.01 por hora por zona.

Precios de lista AWS. Sin free tier. PDF de 2 MiB.
