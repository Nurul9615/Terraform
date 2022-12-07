locals {
  tags = {
  }
  aws_tags = {
  }
}

# Creates an EKS Cluster Role and adds policies to it
resource "aws_iam_role" "eks_cluster" {
  name = var.role_name

  assume_role_policy = var.assume_role_policy
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = var.AmazonEKSClusterPolicy
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
  policy_arn = var.AmazonEKSServicePolicy
  role       = aws_iam_role.eks_cluster.name
}

####################################################

# Generates an IAM Node Role for EKS and adds policies to it
resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "this" {
  key_name = var.key_name

  public_key = tls_private_key.this.public_key_openssh
  
  provisioner "local-exec" { # Create a "eks_key.pem" to your computer
    command = "echo '${tls_private_key.this.private_key_pem}' > ./eks_key.pem"
  }
  tags       = local.aws_tags
}

resource "aws_iam_role" "eks_cluster_role" {
  name               = var.eks_iam_role_name
  assume_role_policy = var.assume_role_policy=
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = var.AmazonEKSWorkerNodePolicy
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = var.AmazonEKS_CNI_Policy
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = var.AmazonEC2ContainerRegistryReadOnly
  role       = aws_iam_role.eks_cluster_role.name
}

####################################################

data "tls_certificate" "eks_tls_cert" {
  url = aws_eks_cluster.aws_eks.identity[0].oidc[0].issuer
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.iam_openid_connect.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:cluster-autoscaler"]
    }
    principals {
      identifiers = [aws_iam_openid_connect_provider.iam_openid_connect.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_openid_connect_provider" "iam_openid_connect" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_tls_cert.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.aws_eks.identity[0].oidc[0].issuer
  tags            = local.tags
}

resource "aws_kms_key" "this" {
  enable_key_rotation = true
}

resource "aws_eks_cluster" "aws_eks" {
  name     = var.eks_name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = var.private_subnets
    endpoint_public_access  = true
    endpoint_private_access = true

    public_access_cidrs = ["0.0.0.0/0"]
  }
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.this.arn
    }
  }
  tags = local.tags
  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]
}

resource "aws_iam_role" "eks_iam_role" {
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  name               = var.clusterautoscalerrole
  inline_policy {
    name = "EKSClusterAutoScalerPolicy"

    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : [
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:DescribeAutoScalingInstances",
            "autoscaling:DescribeLaunchConfigurations",
            "autoscaling:DescribeTags",
            "autoscaling:SetDesiredCapacity",
            "autoscaling:TerminateInstanceInAutoScalingGroup",
            "ec2:DescribeLaunchTemplateVersions"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        }
      ]
    })
  }

  tags = local.aws_tags
}
resource "aws_eks_node_group" "node" {
  cluster_name    = aws_eks_cluster.aws_eks.name
  node_group_name = var.eksnode_name
  node_role_arn   = aws_iam_role.eks_cluster_role.arn
  subnet_ids      = var.private_subnets
  instance_types  = var.instance_types
  capacity_type   = var.capacity_type

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size, remote_access]
  }
  labels = {
    "eks/cluster-name"   = aws_eks_cluster.aws_eks.name
    "eks/nodegroup-name" = format("ng1-%s", aws_eks_cluster.aws_eks.name)
  }
  tags = {
    "k8s.io/cluster-autoscaler/${aws_eks_cluster.aws_eks.name}" = "owned"
    "k8s.io/cluster-autoscaler/enabled"                         = "TRUE"
  }
  scaling_config {
    desired_size = var.desirednode
    max_size     = var.maxnode
    min_size     = var.minnode
  }
  remote_access {
    ec2_ssh_key = var.keyname
  }
}

resource "aws_kms_key" "ecr_kms" {
  enable_key_rotation = true
}

resource "aws_ecr_repository" "ecr" {
  name                 = var.ecr_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr_kms.arn
  }
}