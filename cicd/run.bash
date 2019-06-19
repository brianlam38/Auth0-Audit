#!/bin/bash -eux

# Set to 'test' environment in config file
echo "Running unit tests..."
sed -i "s/ENVIRONMENT=.*/ENVIRONMENT='test'/" config.py
