output "task_execution_role_arn" {
  description = "The ARN of the ECS Task Execution Role"
  value       = aws_iam_role.ecs_service_task_role.arn
}

output "service_name" {
  description = "Name of the ECS Service (for autoscaling configuration)"
  value       = aws_ecs_service.service.name
}

output "cluster_name" {
  description = "Name of the ECS Cluster (for autoscaling configuration)"
  value       = split("/", var.cluster_arn)[1]
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer (use this for manual Route53 configuration when DNS is disabled)"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer (needed for Route53 alias records)"
  value       = aws_lb.main.zone_id
}

output "service_url" {
  description = "URL to access the service (custom domain when DNS enabled, ALB DNS when disabled)"
  value       = var.enable_dns ? "https://${var.dns_prefix}.${var.dns_zone_name}" : "http://${aws_lb.main.dns_name}"
}

output "certificate_arn" {
  description = "ARN of the ACM certificate (if created)"
  value       = var.enable_dns && var.certificate_arn == null && length(aws_acm_certificate.service) > 0 ? aws_acm_certificate.service[0].arn : var.certificate_arn
}

output "certificate_validation_records" {
  description = "DNS validation records for ACM certificate (for manual creation in Route53)"
  value = var.enable_dns && var.certificate_arn == null && length(aws_acm_certificate.service) > 0 ? [
    for dvo in aws_acm_certificate.service[0].domain_validation_options : {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      value  = dvo.resource_record_value
    }
  ] : []
}