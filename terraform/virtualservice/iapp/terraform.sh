#!/bin/bash

export BASE_DIR=`pwd`;
export DIR=terraform/virtualservice/iapp;

cd $BASE_DIR/$DIR;
terraform init;
terraform get -update=true;
terraform apply
