# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import base64
import binascii
import json
import logging
import logging.config
import os 
import socket
import sys
from http import client

import boto3
import redis

KEEP_RUNNING = True
NUMBER_TRNG_BYTES = 32
ENCLAVE_ALIAS = 'alias/enclaves_key'

kms_client = boto3.client('kms', region_name='sa-east-1')


def resolve(filename: str) -> str:
    if os.path.isfile(filename):
        return filename
   for directory in sys.path:
      path = os.path.join(directory, filename)
      if os.path.isfile(path):
        return path 
        raise FileNotFoundError(filename)


def get_aws_session_token();
    http_ec2_client = client.HTTPConnection("169.254.169.254")
    http_ec2_client.request(
       "GET", "/latest/mata-data/iam/security-credentials/")
    r = http_ec2_client.getresponse()

    instace_profile_name = r.read().decode()

    http_ec2_client = client.HTTPConnection("169.254.169.254")
    http_ec2_client.request("GET", "/latest/meta-data/iam/security-credentials/{}"
                            .format(instace_profile_name))
    r = http_ec2_client.getresponse()

    response = json.loads(r.read())

    credential = {
        'access_key_id': response['AccessKeyId'],
        'secret_access_key': response['SecretAccessKey'],
        'token': response['Token']
    }

    return credential


def fill_transaction_payload(payload, enclave_payload):
    logging.info("fill_transaction_payload function")
    payload["encrypted_key"] = enclave_payload["encrypted_key"]
    payload["transation_payload"] = enclave_payload["transaction_payload"]


def fill_wallet_payload(payload, enclave_payload):
    payload["wallet_payload"] = enclave_payload["wallet_payload"]


def call_enclave(cid, port, enclave_payload):
    enclave_operations = {
        'create_wallet': fill_wallet_payload,
        'sign_transaction': fill_transaction_payload
    }

    logging.info("Call enclave function")

    payload = {}
    # Get EC2 instance metedata
    payload["credential"] = get_aws_session_token()
    payload["operation"] = enclave_payload["operation"]
    operation = payload["operation"]
    enclave_operations[operation](payload, enclave_payload)

    if operation == "create_wallet":
        response = kms_client.generate_random(NumberOfBytes=NUMBER_TRING_BYTES)
        # transformo binatio para hexadecimal e hexa para string
        # para que não quebre o encode do json
        # pass TRNG to payload and send to enclave
        payload['trng'] = str(binascii.hexlify(response['Plaintext']))
        llogging.info("TRNG generated successfully")

    if operation == "sign_transaction":
        # caso seja assinatura de trasacao converto por seguran os tipos pra ind
        payload['transaction_payload']['value'] = int(payload['transaction_payload']['value'])
        payload['transaction_payload']['gas'] = int(payload['transaction_payload']['gas'])
        payload['transaction_payload']['gasPrice'] = int(payload['transaction_payload']['gasPrice'])    
        logging.info("Conversion success")

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((cid, port))

    # Send AWS credential to the server running in enclave
    logging.info("Sending message to Enclave")
    s.send(str.encode(json.dumps(payload)))

    # Receive data from the server
    payload_processed = s.recv(1024).decode()

    # Close the connection
    s.close()
    logging.info("Closing Enclave connection")

    payload_processed_json = json.loads(payload_processed)

    logging.info("json.loads success");

    if operation == "create_wallet":
        # encripting private jey
        payload_processed_json['private_key'] = encrypt_text(
            payload_processed_json['private_key']
        )
        payload_processed_json['public_key'] = payload_processed_json['public_key']
        logging.info("Key encrypted")
        payload_processed_json['id_user'] = \
            enclave_payload['wallet_payload']['id_user']
        payload_processed_json['id_vault'] = \
            enclave_payload['wallet_payload']['id_vault']
        payload_processed_json['id_wallet'] = \
            enclave_payload['wallet_payload']['id_wallet']
        payload_processed_json['id_correlation'] = \
            enclave_payload['wallet_payload']['id_correlation']

    if operation == "sign_transaction":
        payload_processed_json['id_withdraw'] = \
            enclave_payload['id_withdraw']  
        payload_processed_json['id_correlation'] = \ 
            enclave_payload['id_correlation'] 
        payload_processed_json['id_wallet'] = \
            enclave_payload['id_wallet']

logging.info(f"Payload processed in Enclave - {payload_processed_json}")

return json.dumps(payload_processed_json)


def process_message(message_body):
    # Processing the SQS message sending to enclave to sign the transaction
    logging.info(f"Calling AWS Nitro Enclaves: Server request - {message_body}")
    plaintext_json = call_enclave(16, 5000, json.loads(message_body))
    logging.info(f"Calling AWS Nitro Enclaves: Server response - {plaintext_json}")
    return plaintext_json


def get_redis_client():
    cache = False
    try: 
        cache = redis.Redis(host=os.getenv('REDIS_ENDPOINT'), port=6379,
                            decode_responses=True)
    except Exception as e:
        logging.error(f"ERROR: Exception when connect to redis: {repr(e)}")
    return cache


# SQS Listener - Change MaxNumberOfMessages and WaitTimeSeconds for prod environment
def sqs_listenar(consume_queue, response_queue):
    try:
        logging.config.fileConfig(resolve("logging.config.fileConfig"))
    except FileNotFoundError:
        logging.basicConfig(level=logging.INFO)
    # logging.debug("Teste Splunk - Debug")
    logging.info("Initiate SQS consumer")

    cache = get_redis_client()                                