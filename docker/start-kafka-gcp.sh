#!/bin/bash

# Get all secrets from GCP Secret Manager
export CLUSTER_ID=$(gcloud secrets versions access latest --secret="kafka-cluster-id")
export JWT_KEY_DEV_ID=$(gcloud secrets versions access latest --secret="jwt-key-dev-id")
export JWT_KEY_DEV_SECRET=$(gcloud secrets versions access latest --secret="jwt-key-dev-secret")
export JWT_KEY_TEST_ID=$(gcloud secrets versions access latest --secret="jwt-key-test-id")
export JWT_KEY_TEST_SECRET=$(gcloud secrets versions access latest --secret="jwt-key-test-secret")
export JWT_ACTIVE_KEYS=$(gcloud secrets versions access latest --secret="jwt-active-keys")
export JWT_DEFAULT_KEY=$(gcloud secrets versions access latest --secret="jwt-default-key")

# Check if all secrets were retrieved successfully
for var in CLUSTER_ID JWT_KEY_DEV_ID JWT_KEY_DEV_SECRET JWT_KEY_TEST_SECRET JWT_KEY_TEST_SECRET JWT_ACTIVE_KEYS JWT_DEFAULT_KEY; do
    if [ -z "${!var}" ]; then
        echo "Error: Failed to retrieve $var from Secret Manager"
        exit 1
    fi
done

# Log what we're doing (but don't show the secret!)
echo "Starting Kafka broker with:"
echo "CLUSTER_ID: $CLUSTER_ID"
echo "JWT_KEY_DEV_ID: $JWT_KEY_DEV_ID"
echo "JWT_KEY_DEV_SECRET: [secured]"
echo "JWT_KEY_TEST_ID: $JWT_KEY_TEST_ID"
echo "JWT_KEY_TEST_SECRET: [secured]"
echo "JWT_ACTIVE_KEYS: $JWT_ACTIVE_KEYS"
echo "JWT_DEFAULT_KEY: $JWT_DEFAULT_KEY"

# Start docker compose
docker compose up -d

echo "Containers started. Check logs with: docker compose logs -f"