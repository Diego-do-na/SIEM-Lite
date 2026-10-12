locals {
    # Athena does not accept dashes in database names
    glue_database_name = "${replace(local.prefix, "-", "_")}_catalog"
}

resource "aws_glue_catalog_database" "catalog" {
    name = local.glue_database_name
}

# The incident_exporter writes one curated JSON line per incident under incidents/day=YYYY-MM-DD/.
# Partition projection lets Athena compute the partitions from the path, so no crawler or ETL job is needed.
# One date partition (not year/month/day): every query must filter on `day`, so Athena only lists the days
# in range instead of every projected partition (a year/month/day layout projects thousands of paths)
resource "aws_glue_catalog_table" "incidents" {
    name = "incidents"
    database_name = aws_glue_catalog_database.catalog.name
    table_type = "EXTERNAL_TABLE"

    parameters = {
        EXTERNAL = "TRUE"
        "projection.enabled" = "true"
        "projection.day.type" = "date"
        "projection.day.format" = "yyyy-MM-dd"
        "projection.day.range" = "2025-01-01,NOW"
        "projection.day.interval" = "1"
        "projection.day.interval.unit" = "DAYS"
        "storage.location.template" = "s3://${aws_s3_bucket.processed.bucket}/incidents/day=$${day}"
    }

    partition_keys {
        name = "day"
        type = "string"
    }

    storage_descriptor {
        location = "s3://${aws_s3_bucket.processed.bucket}/incidents/"
        input_format = "org.apache.hadoop.mapred.TextInputFormat"
        output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

        ser_de_info {
            serialization_library = "org.openx.data.jsonserde.JsonSerDe"
        }

        columns {
            name = "incidentid"
            type = "string"
        }

        columns {
            name = "severity"
            type = "string"
        }

        columns {
            name = "globalscore"
            type = "int"
        }

        columns {
            name = "useridentity"
            type = "string"
        }

        columns {
            name = "sourceipaddress"
            type = "string"
        }

        columns {
            name = "timestamp"
            type = "bigint"
        }

        columns {
            name = "firstseen"
            type = "bigint"
        }

        columns {
            name = "lastseen"
            type = "bigint"
        }

        columns {
            name = "duration"
            type = "bigint"
        }

        columns {
            name = "mitretechniques"
            type = "array<string>"
        }

        columns {
            name = "actionnames"
            type = "array<string>"
        }

        columns {
            name = "eventcount"
            type = "bigint"
        }

        columns {
            name = "responsetaken"
            type = "boolean"
        }

        columns {
            name = "responsesucceeded"
            type = "boolean"
        }

        columns {
            name = "hourutc"
            type = "int"
        }
    }
}
