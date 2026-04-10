variable "aws_region" {
  default = "ap-south-1"
}

variable "instance_type" {
  default = "t2.medium"
}

variable "ami_id" {
  description = "AMI ID for EC2 instance"
  default     = "ami-0c55b159cbfafe1f0"
}