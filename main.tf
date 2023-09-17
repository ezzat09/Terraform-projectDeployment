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

  azs             = ["us-west-2a","us-west-2b","us-west-2c"]
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

# Create a security group for the Cuckoo instance
resource "aws_security_group" "cuckoo_sg" {
  name_prefix = "cuckoo-sg-"

  # Example rule to allow SSH and Cuckoo ports (adjust as needed)
  ingress {
    from_port   = 22
    to_port     = 8090
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Replace with your private subnet CIDR block
  }
}

# Create an EC2 instance for Cuckoo Sandbox in the private subnet
resource "aws_instance" "cuckoo_instance" {
  ami           = "ami-0123456789abcdef0"  # Replace with your Cuckoo AMI ID
  instance_type = "t2.medium"              # Choose an appropriate instance type
  subnet_id     = "subnet-0123456789abcdef1"  # Replace with your private subnet ID

  security_groups = [aws_security_group.cuckoo_sg.name]

  key_name = "your-key-pair-name"  # Replace with your SSH key pair name

  user_data = <<-EOF
              #!/bin/bash
              # Sample user data script for Cuckoo installation and configuration
              # Replace with actual installation and configuration steps
              EOF
}
resource "aws_subnet" "private_subnetforCucko" {
  vpc_id     = aws_vpc.Cuckoo_VPC.id
  cidr_block = "192.168.1.0/22"

  tags = {
    Name = "Main"
  }
}
# Create a Network ACL for the private subnet (adjust rules as needed)
resource "aws_network_acl" "private_subnet_acl" {
  vpc_id    = aws_vpc.Cuckoo_VPC
  # Example rule to allow outbound traffic to specific IP ranges
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Adjust as needed
    rule_action = "allow"
  }

  # Add more rules as required for your use case
}
resource "aws_network_acl_association" "CUCKoomain" {
  network_acl_id = aws_network_acl.CUCKoomain.id
  subnet_id      = aws_subnet.private_subnetforCucko
}
# Create a Route Table for the private subnet and associate it with the subnet
resource "aws_route_table" "private_subnet_route_table" {
  vpc_id = "vpc-0123456789abcdef2"  # Replace with your VPC ID

  # Example route to send traffic to the internet through an internet gateway
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "igw-0123456789abcdef3"  # Replace with your internet gateway ID
  }
}

# Associate the private subnet with the private subnet's route table
resource "aws_route_table_association" "private_subnet_association" {
  subnet_id      = "subnet-0123456789abcdef1"  # Replace with your private subnet ID
  route_table_id = aws_route_table.private_subnet_route_table.id
}

# Create a security group for the firewall (adjust rules as needed)
resource "aws_security_group" "firewall_sg" {
  name_prefix = "firewall-sg-"

  # Example rule to allow incoming traffic from the private subnet
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Replace with your private subnet CIDR block
  }

  # Add more rules as needed for the firewall
}

# Create the firewall EC2 instance in the public subnet with appropriate user data
resource "aws_instance" "firewall_instance" {
  ami           = "ami-0123456789abcdef4"  # Replace with your firewall AMI ID
  instance_type = "t2.micro"               # Choose an appropriate instance type
  subnet_id     = "subnet-0123456789abcdef5"  # Replace with your public subnet ID

  security_groups = [aws_security_group.firewall_sg.name]

  key_name = "your-key-pair-name"  # Replace with your SSH key pair name

  user_data = <<-EOF
              #!/bin/bash
              # Sample user data script for firewall installation and configuration
              # Replace with actual installation and configuration steps
              EOF
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
