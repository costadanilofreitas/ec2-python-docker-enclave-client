# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from app import sqs_listenar

import boto3

sqs = boto3.resource("sqs", region_name="sa-east-1")
new_wallet_queue = sqs.get_queue_by_name(QueueName="new-wallets")
created_wallet_queue = sqs.get_queue_by_name(QueueName="created-wallets")

# SQS Listener - Change MaxNumberOfMessages and WaitTimeSeconds for prod environment
if __name__ == "__main__":
    sqs_listenar(new_wallet_queue, created_wallet_queue)