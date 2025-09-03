#!/bin/bash

# Script to set local Django settings via environment variables
# This script configures DEBUG=False and ALLOWED_HOSTS for localhost only

echo "Setting local Django environment variables..."
echo "=================================================="

export DEBUG='False'
export ALLOWED_HOSTS='localhost,127.0.0.1'
export SECRET_KEY='your-secret-key'
export DB_NAME='trendify_local_db'
export DB_USER='trendify_local_db_user'
export DB_PASSWORD='Yeahyeahyeah1!'

echo "✓ DEBUG = $DEBUG"
echo "✓ ALLOWED_HOSTS = $ALLOWED_HOSTS"
echo "✓ SECRET_KEY = $SECRET_KEY"
echo "=================================================="
echo "Environment variables set successfully!"
