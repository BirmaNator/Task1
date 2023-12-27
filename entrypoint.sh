#!/bin/bash

# Run the Python script with environment variables as default values
python ./task1.py --access-key "${AWS_ACCESS_KEY_ID:-default}" \
                  --secret-key "${AWS_SECRET_ACCESS_KEY:-default}" \
                  --region "${REGION:-default}" \
                  --bucket "${BUCKET:-default}" \
                  "${@}"
