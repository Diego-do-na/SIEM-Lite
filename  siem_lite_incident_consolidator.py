import os
import logging
import time
import uuid
import boto3
from boto3.dynamodb.types import TypeDeserializer

deserializer = TypeDeserializer()
dynamodb = boto3.resource('dynamodb')

bedrock_runtime = boto3.client('bedrock-runtime', config=boto3.session.Config(
    connect_timeout=5,
    read_timeout=15,
    retries={'max_attempts': 1}
))
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Same weights as the detection Lambda, kept in sync for severity recalculation
ACTION_WEIGHTS = {
    'StopLogging': 400,
    'DeleteTrail': 400,
    'DisableKey': 400,
    'ScheduleKeyDeletion': 400,
    'UpdateTrail': 240,
    'DeleteSecurityGroup': 240,
    'AuthorizeSecurityGroupIngress': 200,
    'CreateSecurityGroup': 160,
    'RevokeSecurityGroupIngress': 120,
    'AuthorizeSecurityGroupEgress': 120,
    'RevokeSecurityGroupEgress': 80,
}

MITRE_MAP = {
    'StopLogging': 'T1562.008',
    'DeleteTrail': 'T1562.008',
    'UpdateTrail': 'T1562.008',
    'AuthorizeSecurityGroupIngress': 'T1562.007',
    'AuthorizeSecurityGroupEgress': 'T1562.007',
    'RevokeSecurityGroupIngress': 'T1562.007',
    'RevokeSecurityGroupEgress': 'T1562.007',
    'CreateSecurityGroup': 'T1562.007',
    'DeleteSecurityGroup': 'T1562.007',
    'DisableKey': 'T1485',
    'ScheduleKeyDeletion': 'T1485',
}

def get_severity(score):
    if score >= 600:
        return "CRITICAL"
    elif score >= 400:
        return "HIGH"
    elif score >= 200:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "NONE"

def deserialize_item(dynamodb_json):
    return {k: deserializer.deserialize(v) for k, v in dynamodb_json.items()}

def get_mitre_techniques(item):
    """Collect unique MITRE techniques from every action seen in this incident."""
    techniques = set()

    for action_name in item.get('actionCounts', {}).keys():
        technique = MITRE_MAP.get(action_name)
        if technique:
            techniques.add(technique)
        else:
            # Denied-access actions not in the static map get a generic
            # brute-force/discovery technique when repeated.
            techniques.add('T1110')

    for action_name in item.get('configChanges', {}).keys():
        technique = MITRE_MAP.get(action_name)
        if technique:
            techniques.add(technique)

    return sorted(techniques)

def build_prompt(severity, duration, mitre_techniques, action_counts, config_changes, source_ip):
    actions_summary = ", ".join(
        f"{action} (x{details.get('count', 0)})"
        for action, details in {**action_counts, **config_changes}.items()
    ) or "sin acciones registradas"

    techniques_summary = ", ".join(mitre_techniques) if mitre_techniques else "sin técnica mapeada"

    return f"""Eres un analista de seguridad revisando un incidente ya clasificado por un sistema de detección automatizado. Genera un informe de 4 a 6 oraciones con esta estructura exacta, sin encabezados ni viñetas:

1. Qué ocurrió (resume el patrón de actividad, no listes cada evento).
2. Por qué es notable dado el contexto (severidad, duración, volumen).
3. Qué técnica de amenaza representa (usa el nombre de la técnica MITRE, no solo el código).
4. Una recomendación concreta y accionable para el equipo de seguridad.

Reglas estrictas:
- No repitas números crudos sin interpretarlos (ej. no digas "hubo 5 eventos", di qué implica esa frecuencia).
- No inventes información que no esté en los datos.
- Sé específico al patrón de este incidente, no genérico.

Datos del incidente:
- Severidad: {severity}
- Duración de la actividad: {duration} segundos
- IP de origen: {source_ip}
- Técnicas MITRE ATT&CK involucradas: {techniques_summary}
- Acciones observadas: {actions_summary}"""

def getBedrockInsight(severity, duration, mitre_techniques, action_counts, config_changes, source_ip):
    prompt = build_prompt(severity, duration, mitre_techniques, action_counts, config_changes, source_ip)
    try:
        response = bedrock_runtime.converse(
            modelId = BEDROCK_MODEL_ID,
            messages = [{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig = {"maxTokens": 400, "temperature": 0.3}
        )
        return response['output']['message']['content'][0]['text']
    except Exception as e:
        logger.error(f"Bedrock invocation failed: {str(e)}")
        return "Insight no disponible: fallo en la generación automática. Revisar el incidente manualmente."


def lambda_handler(event, context):
    incident_table_name = os.environ.get('INCIDENT_TABLE_NAME')
    incident_table = dynamodb.Table(incident_table_name)

    for record in event['Records']:
        try:
            old_image = record['dynamodb']['OldImage']
            item = deserialize_item(old_image)

            first_seen = int(item.get('firstSeen', 0))
            last_seen = int(item.get('lastSeen', 0))
            duration = last_seen - first_seen

            global_score = int(item.get('globalCounts', 0))
            severity = get_severity(global_score)

            mitre_techniques = get_mitre_techniques(item)

            incident_id = str(uuid.uuid4())

            insights = getBedrockInsight(severity, duration, mitre_techniques, item.get('actionCounts', {}), item.get('configChanges', {}), item.get('sourceIPAddress'))

            incident_table.put_item(
                Item={
                    'severity': severity,
                    'timestamp': int(time.time()),
                    'incidentId': incident_id,
                    'userIdentity': item.get('userIdentity'),
                    'sourceIPAddress': item.get('sourceIPAddress'),
                    'globalScore': global_score,
                    'firstSeen': first_seen,
                    'lastSeen': last_seen,
                    'duration': duration,
                    'mitreTechniques': mitre_techniques,
                    'actionCounts': item.get('actionCounts', {}),
                    'configChanges': item.get('configChanges', {}),
                    'insights': insights
                }
            )

            logger.info(f"Incident consolidated and stored: severity={severity}, duration={duration}s")

        except Exception as e:
            logger.error(f"Error processing record: {str(e)}")