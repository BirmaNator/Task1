# AWS Security Group Management Script

This Python script is designed to manage AWS Security Groups. It scans all security groups in an AWS account, identifies any rules allowing open access from `0.0.0.0/0`, logs these findings, optionally removes these rules, and uploads the log to an S3 bucket.

## Features

- **Security Group Scanning**: Scans all security groups for inbound rules allowing open access from `0.0.0.0/0`.
- **Logging and Remediation**: Logs identified security groups and optionally removes the insecure inbound rules.
- **S3 Integration**: Uploads the generated logs to a specified S3 bucket for record-keeping and further analysis.
- **AWS Integration**: Utilizes Boto3 to interact with AWS services, including EC2 and S3.

## Prerequisites

- Python 3.6 or higher
- AWS CLI installed and configured, or AWS Access Key ID and Secret Access Key
- `boto3` Python package
- An S3 bucket for uploading logs

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/birmanator/task1.git
   cd your-repository

## How To Execute
1) Locally (terminal): 
   1) Install dependencies:
   ```
   pip install boto3
   ```
   2) Running script with access & secret keys as arguments
   ```
   python task1.py --access-key <ACCESS_KEY> --secret-key <SECRET_KEY> --region <REGION> --bucket <BUCKET_NAME> [--log-mode]
    ```
   ** Running in log mode will not make any changes in your security groups **
2) Running with Docker 
   1) Build image locally
   ```
   docker build -t <DESIRED_IMAGE_NAME> .
    ```
   2) Running Docker Container
      1) Inserting Environment Variables Manually 
      ```commandline
        docker run -e AWS_ACCESS_KEY_ID=<ACCESS_KEY> -e AWS_SECRET_ACCESS_KEY=<SECRET_KEY> --region <REGION> --bucket <BUCKET_NAME> <DESIRED_IMAGE_NAME> [--log-mode]
      ```
      2) Using Environment Variables
      ```
      docker run -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \   
           -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
           -e REGION=<REGION> \
           -e BUCKET=<BUCKET_NAME> \
           <DESIRED_IMAGE_NAME> [--log-mode]
      ``` 
