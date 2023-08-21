# Terraform Settings Block
terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.13.0"
    }
    helm = {
      source = "hashicorp/helm"
      version = "~> 2.5"
    }
    http = {
      source = "hashicorp/http"
      version = "~> 2.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.11"
    }
  }
  # Adding Backend as S3 for Remote State Storage
  backend "s3" {
    bucket = "pwp-terraform-aws-eks"
    key    = "dev/eks-cluster/terraform.tfstate"
    region = "ap-southeast-1"

    # For State Locking
    dynamodb_table = "dev-aws-lbc"
  }
}

# Terraform AWS Provider Block
provider "aws" {
  region = var.aws_region
  # profile = var.aws_profile
}



# Terraform HTTP Provider Block
provider "http" {
  # Configuration options
}