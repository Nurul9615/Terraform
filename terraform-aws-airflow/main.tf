resource "aws_s3_bucket" "dags" {
  bucket = var.mwaa_dag_storage_name
  acl    = "private"

  logging {
    target_bucket = "logs-ACCOUNTNUMBER-eu-west-1"
    target_prefix = "s3accesslogs/s3-mwaadag/"
  }

  force_destroy = true
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
  }

  #lifecycle {
  #  ignore_changes="tags"
  #}
}

resource "aws_s3_bucket_object" "dags_folder" {
  bucket       = aws_s3_bucket.dags.id
  acl          = "private"
  key          = "dags/"
  content_type = "application/x-directory"
}

resource "aws_s3_bucket_object" "workflow_folder" {
  bucket       = aws_s3_bucket.dags.id
  acl          = "private"
  key          = "dags/workflow/"
  content_type = "application/x-directory"
}

resource "aws_s3_bucket_object" "requirements_folder" {
  bucket       = aws_s3_bucket.dags.id
  acl          = "private"
  key          = "requirements/"
  content_type = "application/x-directory"
}

resource "aws_kms_key" "kms" {
  description         = "mwaakey"
  enable_key_rotation = true
}

resource "aws_kms_alias" "kms" {
  name          = "alias/MWAA01"
  target_key_id = aws_kms_key.kms.key_id
}

# iam role
resource "aws_iam_role" "mwaa_role" {
  name                 = var.mwaa_iam_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "airflow-env.amazonaws.com"
        }
      },
    ]
  })
}

# 
resource "aws_iam_role_policy" "mwaa_policy" {
  name = "MwaaPolicy"
  role = aws_iam_role.mwaa_role.id
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "airflow:PublishMetrics",
            "Sid": "cdpmwaapolicy",
            "Resource": "arn:aws:airflow:eu-west-1:ACCOUNTNUMBER:environment/mwaa-name"
        },
        {
            "Effect": "Deny",
            "Action": "s3:ListAllMyBuckets",
            "Resource": [
                "arn:aws:s3:::s3-dagbucket-arn",
                "arn:aws:s3:::s3-dagbucket-arn/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject*",
                "s3:GetBucket*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::s3-dagbucket-arn",
                "arn:aws:s3:::s3-dagbucket-arn/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject*",
                "s3:GetBucket*",
                "s3:PutObject*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::s3-bucket-arn",
                "arn:aws:s3:::s3-bucket-arn/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:GetLogRecord",
                "logs:GetLogGroupFields",
                "logs:GetQueryResults"
            ],
            "Resource": [
                "arn:aws:logs:eu-west-1:ACCOUNTNUMBER:log-group:airflow-name-*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "cloudwatch:PutMetricData",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sqs:ChangeMessageVisibility",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes",
                "sqs:GetQueueUrl",
                "sqs:ReceiveMessage",
                "sqs:SendMessage"
            ],
            "Resource": "arn:aws:sqs:eu-west-1:*:airflow-celery-*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

# mwaa environment
resource "aws_mwaa_environment" "mwaa" {
  dag_s3_path        = "dags/"
  execution_role_arn = aws_iam_role.mwaa_role.arn
  #dag_s3_path                   = "dags"
  #execution_role_arn            = aws_iam_role.mwaa_role.arn
  #airflow_version               = "2.2.2"
  #max_workers                   = 2
  #requirements_s3_path          = "requirements/requirements.txt"
  #kms_key                       = aws_kms_key.kms.arn

  #airflow_configuration_options = {"secrets.backend" = "airflow.providers.amazon.aws.secrets.secrets_manager.SecretsManagerBackend", "secrets.backend_kwargs" = "{\"connections_prefix\" : \"airflow/connections\", \"variables_prefix\" : \"airflow/variables\"}"}
  #airflow_configuration_options = {"secrets.backend" = "airflow.contrib.secrets.aws_secrets_manager.SecretsManagerBackend", "secrets.backend_kwargs" = "{\"connections_prefix\" : \"airflow/connections\", \"variables_prefix\" : \"airflow/variables\"}"}

  logging_configuration {
    dag_processing_logs {
      enabled   = true
      log_level = "DEBUG"
    }

    scheduler_logs {
      enabled   = true
      log_level = "INFO"
    }

    task_logs {
      enabled   = true
      log_level = "WARNING"
    }

    webserver_logs {
      enabled   = true
      log_level = "ERROR"
    }

    worker_logs {
      enabled   = true
      log_level = "CRITICAL"
    }
  }

  name = var.mwaa_environment_name

  network_configuration {
    security_group_ids = var.security_group_ids
    subnet_ids         = var.subnet_ids
  }

  source_bucket_arn = aws_s3_bucket.dags.arn

  tags = {
  }
}
