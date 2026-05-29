resource "aws_security_group" "reach_testbed_open_admin" {
  name        = "reach-testbed-open-admin"
  description = "Synthetic IaC fixture with intentionally broad ingress."

  ingress {
    description = "Synthetic open admin port"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
