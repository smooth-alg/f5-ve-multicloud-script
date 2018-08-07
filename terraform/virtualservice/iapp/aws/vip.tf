
variable bigip_address   { default = "10.0.0.11" }
variable bigip_username  { default = "admin" }
variable bigip_password  { default = "admin" }

variable partition               { default = "Common"       }
variable service_name            { default = "www"       }
variable vs_address              { default = "0.0.0.0/0" }
variable vs_port                 { default = "444"        }
variable client_ssl_cert_name    { default = "default"   }
variable ltm_policy_name         { default = "app-ltm-policy" }
variable applicationPoolTagKey   { default = "application" }
variable applicationPoolTagValue { default = "www-v0.0.1" }
variable aws_region              { default = "us-west-2" }

#### RESOURCES ####

terraform {
  backend "local" {
    path = "/var/tmp/f5-demo-app-terraform-aws/terraform.tfstate"
  }
}


provider "bigip" {
  address  = "${var.bigip_address}"
  username = "${var.bigip_username}"
  password = "${var.bigip_password}"
}


####  Create Pool
####  w/ Service Discovery iApp

data "template_file" "iApp_sd_json_payload" {
  template = "${file("${path.module}/f5.service_discovery")}"
  vars {
    partition                 = "${var.partition}"
    service_name              = "${var.service_name}"
    aws_region                = "${var.aws_region}"
    applicationPoolTagKey     = "${var.applicationPoolTagKey}"
    applicationPoolTagValue   = "${var.applicationPoolTagValue}"
  }
}

resource "bigip_sys_iapp" "iApp_sd" {
  name ="${var.service_name}_sd"
  jsonfile ="${data.template_file.iApp_sd_json_payload.rendered}"
}

####  Create Virtual Service
####  w/ v1 http iApp

data "template_file" "iApp_json_payload" {
  template = "${file("${path.module}/https_vip_w_waf_f5.http.v1.2.0rc7")}"
  vars {
    partition                 = "${var.partition}"
    service_name              = "${var.service_name}"
    vs_address                = "${var.vs_address}"
    vs_port                   = "${var.vs_port}"
    ltm_policy_name           = "${var.ltm_policy_name}"
    client_ssl_cert_name      = "${var.client_ssl_cert_name}"
    application_poolName      = "/${var.partition}/${var.service_name}_sd.app/${var.service_name}_sd_pool"
  }
}

resource "bigip_sys_iapp" "iApp" {
  name ="${var.service_name}"
  jsonfile ="${data.template_file.iApp_json_payload.rendered}" 
  depends_on = ["bigip_sys_iapp.iApp_sd"]
}
