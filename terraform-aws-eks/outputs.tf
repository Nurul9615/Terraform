output "EKSclustername" {
  value = aws_eks_cluster.aws_eks.name
}
output "EKSclusterautoscalerrole" {
  value = aws_iam_role.eks_iam_role.arn
}
output "eksrolearn" {
  description = "EKS cluster role"
  value       = aws_iam_role.eks_cluster.arn
}
output "eksnoderolearn" {
  description = "EKS cluster node role"
  value       = aws_iam_role.eks_cluster_role.arn
}
output "eks_worker_node_policy" {
  description = "EKS cluster node role policy1"
  value       = aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy
}
output "eks_cni_policy" {
  description = "EKS cluster node role policy2"
  value       = aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy
}
output "eks_container_registry_policy" {
  description = "EKS cluster node role policy3"
  value       = aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly
}
output "public_key" {
  value = tls_private_key.this.public_key_openssh
}
output "private_key" {
  value = tls_private_key.this.private_key_pem
}
output "keyname" {
  value = aws_key_pair.this.key_name
}