output "environment_url" {
  value = module.blog_alb.lb_dns_name
}
output "cuckoo_user_data" {
  value = data.aws_instance.cuckoo_instance.user_data
}