#!/bin/bash -e

# Small bash wrapper around terraform to support 
# Spinnaker Script Stage which only runs in a single "command" context
# Also since script runs from git repo, need to store state in remote location
# https://www.terraform.io/docs/backends/index.html
# so doesn't get wiped with every pull (see vip.tf )

#export TF_LOG=DEBUG;
export BASE_DIR=`pwd`;
# folder in git repo
export DIR=terraform/virtualservice/iapp/azure;
cd $BASE_DIR/$DIR;

# Initialize terraform custom F5 provider
terraform init;
terraform get -update=true;

terraform_command="terraform apply -lock=false -auto-approve";

echo "${terraform_command} $@";
${terraform_command} $@



