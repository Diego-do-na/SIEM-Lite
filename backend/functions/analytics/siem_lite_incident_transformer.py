import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame
from awsgluedq.transforms import EvaluateDataQuality
from pyspark.sql import functions as F

# Bucket names come from the job arguments (set by Terraform), never hardcoded
args = getResolvedOptions(sys.argv, ['JOB_NAME', 'RAW_BUCKET', 'PROCESSED_BUCKET'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# Default ruleset used by all target nodes with data quality enabled
DEFAULT_DATA_QUALITY_RULESET = """
    Rules = [
        ColumnCount > 0
    ]
"""

# Read raw incident JSON. transformation_ctx is what lets Job Bookmark track
# which S3 objects were already processed across runs — keep it unchanged.
AmazonS3_node1787707613623 = glueContext.create_dynamic_frame.from_options(
    format_options={"multiLine": "false"},
    connection_type="s3",
    format="json",
    connection_options={
        "paths": [f"s3://{args['RAW_BUCKET']}/"],
        "recurse": True
    },
    transformation_ctx="AmazonS3_node1787707613623"
)

EvaluateDataQuality().process_rows(
    frame=AmazonS3_node1787707613623,
    ruleset=DEFAULT_DATA_QUALITY_RULESET,
    publishing_options={
        "dataQualityEvaluationContext": "EvaluateDataQuality_node1787707573002",
        "enableDataQualityResultsPublishing": True
    },
    additional_options={
        "dataQualityResultsPublishing.strategy": "BEST_EFFORT",
        "observations.scope": "ALL"
    }
)

# Derive year/month/day partitions from the incident's own `timestamp` field
# (set by siem_lite_incident_consolidator at write time) — not from the S3
# key layout, so this works regardless of how the exporter names objects.
df = AmazonS3_node1787707613623.toDF()
df = (
    df.withColumn("year", F.date_format(F.from_unixtime(F.col("timestamp")), "yyyy"))
    .withColumn("month", F.date_format(F.from_unixtime(F.col("timestamp")), "MM"))
    .withColumn("day", F.date_format(F.from_unixtime(F.col("timestamp")), "dd"))
)
partitioned_dyf = DynamicFrame.fromDF(df, glueContext, "partitioned_dyf")

AmazonS3_node1787707763660 = glueContext.write_dynamic_frame.from_options(
    frame=partitioned_dyf,
    connection_type="s3",
    format="glueparquet",
    connection_options={
        "path": f"s3://{args['PROCESSED_BUCKET']}/",
        "partitionKeys": ["year", "month", "day"]
    },
    format_options={"compression": "snappy"},
    transformation_ctx="AmazonS3_node1787707763660"
)

job.commit()