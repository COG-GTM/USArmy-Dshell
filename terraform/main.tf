resource "aws_ecs_task_definition" "dshell" {
  family                   = "dshell"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([{
    name  = "dshell"
    image = "dshell:latest"
    
    mountPoints = [{
      sourceVolume  = "pcap-data"
      containerPath = "/data"
    }]
    
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/dshell"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "dshell"
      }
    }
  }])

  volume {
    name = "pcap-data"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.dshell_pcap.id
      root_directory = "/"
    }
  }
}
