output "instance_id" {
  value = aws_instance.this.id
}

output "public_ip" {
  value = aws_instance.this.public_ip
}

output "ssh_command" {
  value = "ssh -i /Users/heobyeong-ug/Documents/Byeongwook.pem ubuntu@${aws_instance.this.public_ip}"
}

output "report_path" {
  value = "/opt/vault-cross-namespace/report.json"
}
