output "instance_id" {
  value = aws_instance.scanner_server.id
}

output "public_ip" {
  value = aws_instance.scanner_server.public_ip
}