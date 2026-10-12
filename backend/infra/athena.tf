resource "aws_athena_workgroup" "this" {
    name = "${local.prefix}-workgroup"
    # Without this, a destroy fails once the workgroup has query history
    force_destroy = true

    configuration {
        # The workgroup settings win over whatever each query asks for
        enforce_workgroup_configuration = true
        # Any single query that would scan more than 1 GB is cancelled
        bytes_scanned_cutoff_per_query = 1073741824

        result_configuration {
            output_location = "s3://${aws_s3_bucket.athena_results.bucket}/"

            encryption_configuration {
                encryption_option = "SSE_S3"
            }
        }
    }
}