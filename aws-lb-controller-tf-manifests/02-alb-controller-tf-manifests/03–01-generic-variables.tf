# AWS Region
variable "aws_region" {
  description = "Region in which AWS Resources to be created"
  type        = string
  default     = "ap-southeast-1"
}
# Environment Variable
variable "environment" {
  description = "Environment Variable used as a prefix"
  type        = string
  default     = "stag"
}
# Business Division
variable "business_division" {
  description = "Business Division"
  type        = string
  default     = "devops"
}