locals {
    # Edit this path to wherever the transformer script lives in the repo
    glue_script_path = "${path.module}/../functions/analytics/siem_lite_incident_transformer.py"
    # Athena does not accept dashes in database names
    glue_database_name = "${replace(local.prefix, "-", "_")}_catalog"
}

resource "aws_glue_catalog_database" "catalog" {
    name = local.glue_database_name
}

# The script is uploaded from the repo, so the Job always runs the versioned code
resource "aws_s3_object" "transformer_script" {
    bucket = aws_s3_bucket.glue_assets.id
    key = "scripts/siem_lite_incident_transformer.py"
    source = local.glue_script_path
    etag = filemd5(local.glue_script_path)
}

resource "aws_glue_job" "incident_transformer" {
    name = "${local.prefix}-incident-transformer"
    role_arn = aws_iam_role.glue.arn
    glue_version = "5.1"
    worker_type = "G.1X"
    number_of_workers = 2
    timeout = 30

    command {
        name = "glueetl"
        python_version = "3"
        script_location = "s3://${aws_s3_bucket.glue_assets.bucket}/${aws_s3_object.transformer_script.key}"
    }

    default_arguments = {
        "--job-language" = "python"
        # Bookmark enabled: without it every run would reprocess and duplicate all of raw
        "--job-bookmark-option" = "job-bookmark-enable"
        "--enable-glue-datacatalog" = ""
        "--enable-metrics" = ""
        "--enable-job-insights" = "true"
        "--enable-observability-metrics" = "true"
        "--enable-continuous-cloudwatch-log" = "true"
        "--enable-spark-ui" = "true"
        "--spark-event-logs-path" = "s3://${aws_s3_bucket.glue_assets.bucket}/sparkHistoryLogs/"
        "--TempDir" = "s3://${aws_s3_bucket.glue_assets.bucket}/temporary/"
        "--conf" = "spark.eventLog.rolling.enabled=true --conf spark.sql.catalog.glue_catalog.glue.skip-name-validation=true"
        "--RAW_BUCKET" = aws_s3_bucket.raw.bucket
        "--PROCESSED_BUCKET" = aws_s3_bucket.processed.bucket
    }
}

resource "aws_glue_crawler" "incident_crawler" {
    name = "${local.prefix}-incident-crawler"
    role = aws_iam_role.glue.arn
    database_name = aws_glue_catalog_database.catalog.name

    s3_target {
        path = "s3://${aws_s3_bucket.processed.bucket}/"
    }

    schema_change_policy {
        update_behavior = "UPDATE_IN_DATABASE"
        delete_behavior = "DEPRECATE_IN_DATABASE"
    }
}

resource "aws_glue_workflow" "analytics" {
    name = "${local.prefix}-analytics-workflow"
}

resource "aws_glue_trigger" "weekly_etl" {
    name = "${local.prefix}-weekly-etl-trigger"
    type = "SCHEDULED"
    schedule = "cron(0 5 ? * SUN *)"
    workflow_name = aws_glue_workflow.analytics.name
    # Same switch as the EventBridge rules, so a test deployment does not run the Job on its own
    start_on_creation = var.enable_event_rules

    actions {
        job_name = aws_glue_job.incident_transformer.name
    }
}

resource "aws_glue_trigger" "crawler_after_etl" {
    name = "${local.prefix}-crawler-after-etl-trigger"
    type = "CONDITIONAL"
    workflow_name = aws_glue_workflow.analytics.name
    start_on_creation = var.enable_event_rules

    predicate {
        conditions {
            job_name = aws_glue_job.incident_transformer.name
            state = "SUCCEEDED"
        }
    }

    actions {
        crawler_name = aws_glue_crawler.incident_crawler.name
    }
}