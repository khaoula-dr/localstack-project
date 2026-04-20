# ─────────────────────────────────────────────────────────────
# F-01 : Bucket S3 — Accès public non bloqué (CKV_AWS_18)
# ─────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-bucket-devsecops"

  tags = {
    Name        = "VulnerableBucket"
    Environment = "dev"
    Faille      = "F-01-F-04"
  }
}

# ─────────────────────────────────────────────────────────────
# F-02 : Security Group — Port SSH ouvert à 0.0.0.0/0 (CKV_AWS_25)
# ─────────────────────────────────────────────────────────────
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Security group avec SSH ouvert — faille intentionnelle F-02"

  ingress {
    description = "SSH ouvert au monde entier"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # FAILLE : SSH exposé publiquement
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name   = "VulnerableSG"
    Faille = "F-02"
  }
}

# ─────────────────────────────────────────────────────────────
# F-03 : IAM Role Policy — Permissions trop larges (CKV_AWS_40)
# ─────────────────────────────────────────────────────────────
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = aws_iam_role.vulnerable_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"          # FAILLE : wildcard Action => trop permissif
      Resource = "*"          # FAILLE : wildcard Resource
    }]
  })
}

# ─────────────────────────────────────────────────────────────
# F-05 : EC2 Instance — IMDSv2 non forcé (CKV_AWS_79)
# ─────────────────────────────────────────────────────────────
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-00000000"          # AMI fictive pour LocalStack
  instance_type = "t2.micro"

  # FAILLE : metadata_options absent ou http_tokens = "optional"
  # IMDSv2 non forcé => vulnérable aux attaques SSRF sur le metadata endpoint
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"            # FAILLE : doit être "required" pour IMDSv2
  }

  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]

  tags = {
    Name   = "VulnerableInstance"
    Faille = "F-05"
  }
}
