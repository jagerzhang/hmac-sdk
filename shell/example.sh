#!/bin/bash
#############################################
# Function: 网关HMAC认证测试脚本              
# Author: Jager                             
# Last Modify Date :2021-12-12              
#############################################

HMAC_USER="<HMAC_USER>"
HMAC_SECRET="<HMAC_SECRET>"
API_URL="http://<API_URL>"

headers=$(bash hmac_auth.sh ${HMAC_USER} ${HMAC_SECRET})
echo $headers
echo
bash -c "curl $API_URL $headers"
echo
