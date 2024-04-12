# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from app import sqs_listenar

import boto3

sqs = boto3.resource("sqs", region_name="sa-east-1")
unsigned_queue = sqs.get_queue_by_name(QueueName="unsigned_transactions")
signed_queue = sqs.get_queue_by_name(QueueName="signed-transactions")

# SQS Listener - Change MaxNumberOfMessages and WaitTimeSeconds for prod environment
if __name__ == "__main__":
    sqs_listenar(unsigned_queue, signed_queue)