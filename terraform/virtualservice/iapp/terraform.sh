#!/bin/bash

export BASE_DIR=`pwd`;
export DIR=terraform/virtualservice/iapp;

# echo "1="
# echo $1
# echo "2="
# echo $2
# echo "3="
# echo $3
# echo "4="
# echo $4
# echo "5="
# echo $5

cd $BASE_DIR/$DIR;
terraform init;
terraform get -update=true;
terraform apply -auto-approve -var $1 -var $2 -var $3 -var $4 -var $5

