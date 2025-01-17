#!/bin/bash

# Wait for Kafka to start
sleep 20

# Kafka broker: Full access to everything
kafka-acls --bootstrap-server broker:9094 \
--add --allow-principal User:kafka-broker \
--operation All --resource-pattern-type prefixed --topic '*'

# Solver: Full admin access to everything
kafka-acls --bootstrap-server broker:9094 \
  --add --allow-principal User:solver \
  --operation All --topic '*' --group '*'

# Resource_provider permissions (matching JWT subject pattern rp_*):
# Write access to all topics
kafka-acls --bootstrap-server broker:9094 \
  --add --allow-principal User:rp_* \
  --operation Write --topic '*'

kafka-acls --bootstrap-server broker:9094 --list