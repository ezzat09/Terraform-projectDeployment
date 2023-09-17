data "aws_ami" "app_ami" {
  most_recent = true

  filter {
    name   = "name"
    values = [var.ami_filter.name]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = [var.ami_filter.owner]
}

resource "aws_vpc" "Cuckoo_VPC" {
  cidr_block       = "192.168.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "Cuckoo_PrivateVPC"
  }
}
module "blog_vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = var.environment.name
  cidr = "${var.environment.network_prefix}.0.0/16"

  azs             = ["eu-west-2a","eu-west-2b","eu-west-2c"]
  public_subnets  = ["${var.environment.network_prefix}.101.0/24", "${var.environment.network_prefix}.102.0/24", "${var.environment.network_prefix}.103.0/24"]

  tags = {
    Terraform = "true"
    Environment = var.environment.name
  }
}


module "blog_autoscaling" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "6.5.2"

  name = "${var.environment.name}-blog"

  min_size            = var.asg_min
  max_size            = var.asg_max
  vpc_zone_identifier = module.blog_vpc.public_subnets
  target_group_arns   = module.blog_alb.target_group_arns
  security_groups     = [module.blog_sg.security_group_id]
  instance_type       = var.instance_type
  image_id            = data.aws_ami.app_ami.id
}

module "blog_alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 6.0"

  name = "${var.environment.name}-blog-alb"

  load_balancer_type = "application"

  vpc_id             = module.blog_vpc.vpc_id
  subnets            = module.blog_vpc.public_subnets
  security_groups    = [module.blog_sg.security_group_id]

  target_groups = [
    {
      name_prefix      = "${var.environment.name}-"
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"
    }
  ]

  http_tcp_listeners = [
    {
      port               = 80
      protocol           = "HTTP"
      target_group_index = 0
    }
  ]

  tags = {
    Environment = var.environment.name
  }
}

module "blog_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.13.0"

  vpc_id  = module.blog_vpc.vpc_id
  name    = "${var.environment.name}-blog"
  ingress_rules = ["https-443-tcp","http-80-tcp"]
  ingress_cidr_blocks = ["0.0.0.0/0"]
  egress_rules = ["all-all"]
  egress_cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group" "cuckoo_sg" {
  name_prefix = "cuckoo-sg-"

  # Example rule to allow SSH and Cuckoo ports (adjust as needed)
  ingress {
    from_port   = 22
    to_port     = 8090
    protocol    = "tcp"
    cidr_blocks = ["192.168.0.0/16"]  # Replace with your private subnet CIDR block
  }
}
resource "aws_subnet" "private_subnetforCucko" {
  vpc_id     = aws_vpc.Cuckoo_VPC.id
  cidr_block = "192.168.0.0/16"

  tags = {
    Name = "Main"
  }
}
# Create an EC2 instance for Cuckoo Sandbox in the private subnet
resource "aws_instance" "cuckoo_instance" {
  ami           = "ami-0123456789abcdef0"  
  instance_type = "t3.nano"              
  subnet_id     = aws_subnet.private_subnetforCucko.id # Replace with your private subnet ID

  security_groups = [aws_security_group.cuckoo_sg.name]

  key_name = "cuckoo-ssh-key"  

  user_data = <<-EOF
              #!/bin/bash
              # Sample user data script for Cuckoo installation and configuration
              # Replace with actual installation and configuration steps
              sudo apt-get update -y
              sudo apt-get upgrade -y
              sudo apt-get install -y python python-pip python-dev python-virtualenv libffi-dev libssl-dev build-essential

              # Install Cuckoo dependencies
              sudo apt-get install -y libjpeg-dev zlib1g-dev swig ssdeep tcpdump mongodb

              # Install Cuckoo Sandbox
              sudo pip install cuckoo

              # Start Cuckoo
              cuckoo -d > /tmp/cuckoo_output.txt
              EOF
}
data "aws_instance" "cuckoo_instance" {
  instance_id = aws_instance.cuckoo_instance.id
}
# Create logs for Cuckoo instance (adjust as needed)
resource "aws_cloudwatch_log_group" "cuckoo_logs" {
  name = "/var/log/cuckoo"
}

# Create a CloudWatch log stream for Cuckoo logs (adjust as needed)
resource "aws_cloudwatch_log_stream" "cuckoo_log_stream" {
  name           = "cuckoo"
  log_group_name = aws_cloudwatch_log_group.cuckoo_logs.name
}
