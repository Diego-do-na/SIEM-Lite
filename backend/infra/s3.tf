locals {
    data_buckets = {
        raw = aws_s3_bucket.raw.id
        processed = aws_s3_bucket.processed.id
        athena_results = aws_s3_bucket.athena_results.id
    }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "raw" {
    bucket = "${local.prefix}-incident-data-raw-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "processed" {
    bucket = "${local.prefix}-incident-data-processed-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "athena_results" {
    bucket = "${local.prefix}-athena-query-results-${data.aws_caller_identity.current.account_id}"
}


resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
    for_each = local.data_buckets
    bucket = each.value

    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
}

resource "aws_s3_bucket_public_access_block" "this" {
    for_each = local.data_buckets
    bucket = each.value

    block_public_acls = true
    ignore_public_acls = true
    block_public_policy = true
    restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
    bucket = aws_s3_bucket.athena_results.id

    rule {
        id = "expire-query-results"
        status = "Enabled"

        filter {}

        expiration {
            days = 30
        }
    }
}