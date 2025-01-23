# JWT Authentication Setup for Kafka

## Configure Firewall
```bash
gcloud auth login
gcloud config set project [PROJECT_NAME]
gcloud compute firewall-rules create allow-kafka \
  --allow tcp:9094 \
  --target-tags=kafka-broker \
  --description="Allow Kafka SASL port"

# Add the network tag to your VM
gcloud compute instances list

gcloud compute instances add-tags [INSTANCE NAME] \
  --tags=kafka-broker \
  --zone=[ZONE]
```

## Setup .env
To start, create a `.env` file that contains the necessary environment variables for your application. This file will be used to store sensitive information locally before transitioning to Google Cloud Secret Manager.

```bash
cp .env.sample .env
```

```bash
# Get the test and dev environment secrets from Doppler
JWT_KEY_TEST_SECRET=<from-doppler>
JWT_KEY_DEV_SECRET=<from-doppler>
```


____

## TODO
Set up secrets with Google Cloud Secret Manager. Refer to the [Google Cloud Secret Manager documentation](https://cloud.google.com/secret-manager/docs) for guidance on creating and managing secrets.

## Prerequisites

- Google Cloud CLI (`gcloud`) installed and configured
- Appropriate Google Cloud project permissions

## Setup Steps

### 1. Enable Google Cloud Secret Manager

```bash
gcloud services enable secretmanager.googleapis.com
```

### 2. Create Required Secrets

Create secrets (you'll be prompted to enter the secret values):

```bash
gcloud secrets create jwt-key-1-secret --data-file=-
gcloud secrets create jwt-key-2-secret --data-file=-
gcloud secrets create jwt-active-keys --data-file=-
gcloud secrets create jwt-default-key --data-file=-
```

### 3. Set Up Service Account

1. Create a service account:

    ```bash
    gcloud iam service-accounts create kafka-vm-sa
    ```

2. Grant secret access permissions:

    ```bash
    export PROJECT_ID="your-project-id"
    ```

3. Grant access to all required secrets:

    ```bash
    for SECRET in jwt-key-1-secret jwt-key-2-secret jwt-active-keys jwt-default-key; do
        gcloud secrets add-iam-policy-binding $SECRET \
        --member="serviceAccount:kafka-vm-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
        --role="roles/secretmanager.secretAccessor"
    done
    ```

### 4. Assign Service Account to VM

```bash
gcloud compute instances set-service-account kafka-broker \
--service-account=kafka-vm-sa@${PROJECT_ID}.iam.gserviceaccount.com
```

### 5. Environment Variables

Run the shell script

```bash
chmod +x docker/start-kafka-gcp.sh
./docker/start-kafka-gcp.sh
```
