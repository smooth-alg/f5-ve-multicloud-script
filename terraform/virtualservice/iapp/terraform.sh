#!/bin/bash -e

export BASE_DIR=`pwd`;
export DIR=terraform/virtualservice/iapp;
export TF_LOG=DEBUG;

terraform_command="terraform apply -lock=false -auto-approve";

cd $BASE_DIR/$DIR;
terraform init;
terraform get -update=true;

echo "${terraform_command} $@";
${terraform_command} $@



