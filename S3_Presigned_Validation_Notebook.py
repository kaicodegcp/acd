# Databricks notebook source
# MAGIC %md
# MAGIC # S3 Pre-signed URL / VPC Interface / FIPS Validation
# MAGIC Run on the intended Databricks compute. Configure the widgets below. This notebook tests HTTP GET/PUT and records sanitized evidence. **HTTP success alone does not prove private routing**: correlate AWS CloudTrail data events, VPC endpoint IDs and flow logs with the S3/network team.
# MAGIC
# MAGIC **Security:** Do not print or persist full pre-signed URLs. They contain temporary credentials. Use a dedicated non-sensitive test prefix. For a Databricks Serverless NCC private endpoint, test the documented regional S3 host and validate private routing using AWS-side evidence; do not assume an endpoint-specific `vpce` DNS name is reachable.

# COMMAND ----------

import boto3
import requests
import socket
import json
import hashlib
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit
from botocore.config import Config

for name, default in [
    ("region", "us-east-1"),
    ("bucket", "REPLACE_WITH_TEST_BUCKET"),
    ("prefix", "presigned-validation"),
    ("vpce_endpoint_base_url", ""),
    ("run_vpce", "false"),
    ("run_fips", "true"),
    ("run_negative_test", "true"),
]:
    dbutils.widgets.text(name, default)

REGION = dbutils.widgets.get("region").strip()
BUCKET = dbutils.widgets.get("bucket").strip()
PREFIX = dbutils.widgets.get("prefix").strip().strip("/")
VPCE_BASE = dbutils.widgets.get("vpce_endpoint_base_url").strip().rstrip("/")
RUN_VPCE = dbutils.widgets.get("run_vpce").lower() == "true"
RUN_FIPS = dbutils.widgets.get("run_fips").lower() == "true"
RUN_NEGATIVE = dbutils.widgets.get("run_negative_test").lower() == "true"

if not REGION or not BUCKET or BUCKET == "REPLACE_WITH_TEST_BUCKET":
    raise ValueError("Set region and bucket widgets before running")
if RUN_VPCE and not VPCE_BASE.startswith("https://"):
    raise ValueError("Set an approved https:// VPC interface endpoint base URL, or disable run_vpce")

RUN_ID = uuid.uuid4().hex[:12]
TEST_BYTES = ("Databricks presigned connectivity validation run=" + RUN_ID).encode("utf-8")
RESULTS = []


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def hostname(url):
    return urlsplit(url).hostname or ""


def client(endpoint_url=None):
    return boto3.client(
        "s3", region_name=REGION, endpoint_url=endpoint_url,
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
    )


def log(scenario, operation, status, http_status=None, host="", key="", details=""):
    row = {
        "run_id": RUN_ID, "timestamp_utc": utc_now(), "scenario": scenario,
        "operation": operation, "status": status,
        "http_status": http_status, "hostname": host,
        "bucket": BUCKET, "object_key": key,
        "details": str(details)[:300],
    }
    RESULTS.append(row)
    print(json.dumps(row))  # no signed URL, headers, or response body


def signed_request(s3, scenario, operation, key, expected_data=TEST_BYTES):
    method = "PUT" if operation == "PUT" else "GET"
    api = "put_object" if operation == "PUT" else "get_object"
    try:
        signed_url = s3.generate_presigned_url(
            api, Params={"Bucket": BUCKET, "Key": key},
            ExpiresIn=900, HttpMethod=method
        )
        host = hostname(signed_url)
        if operation == "PUT":
            response = requests.put(signed_url, data=expected_data, timeout=45)
            ok = response.status_code == 200
            detail = "PUT HTTP status checked; verify object with corresponding GET"
        else:
            response = requests.get(signed_url, timeout=45)
            ok = response.status_code == 200 and response.content == expected_data
            detail = "GET HTTP status and SHA-256 content match=" + str(ok)
        log(scenario, operation, "PASS" if ok else "FAIL", response.status_code,
            host, key, detail)
        return ok
    except Exception as exc:
        # Do not log exception message: HTTP libraries may embed signed URLs in errors.
        log(scenario, operation, "FAIL", None, "", key, type(exc).__name__)
        return False


def test_pair(scenario, s3):
    key = f"{PREFIX}/{RUN_ID}/{scenario.lower().replace(' ', '-')}.txt"
    put_ok = signed_request(s3, scenario, "PUT", key)
    if put_ok:
        signed_request(s3, scenario, "GET", key)
    else:
        log(scenario, "GET", "SKIP", None, "", key, "PUT did not succeed")
    return key

# COMMAND ----------
# MAGIC %md
# MAGIC ## Test 1: Standard S3 pre-signed PUT and GET

# COMMAND ----------

standard = client()
standard_key = test_pair("Standard S3", standard)

# COMMAND ----------
# MAGIC %md
# MAGIC ## Test 2: S3 FIPS pre-signed PUT and GET
# MAGIC FIPS endpoint availability depends on region and service support. This tests the FIPS hostname, **not** FIPS private routing by itself.

# COMMAND ----------

if RUN_FIPS:
    fips_base = f"https://s3-fips.{REGION}.amazonaws.com"
    test_pair("S3 FIPS", client(fips_base))
else:
    log("S3 FIPS", "PUT/GET", "SKIP", details="run_fips=false")

# COMMAND ----------
# MAGIC %md
# MAGIC ## Test 3: Explicit S3 VPC interface endpoint PUT and GET (optional)
# MAGIC Provide the AWS-approved endpoint-specific base hostname in `vpce_endpoint_base_url` only when the compute can reach it. Example bucket-specific base hostname pattern: `https://bucket.vpce-xxxx.s3.region.vpce.amazonaws.com` (confirm the exact DNS name and supported signing pattern with the S3 team). A `200` still requires endpoint/flow-log evidence. **For Databricks Serverless NCC, leave this off unless explicitly instructed.**

# COMMAND ----------

if RUN_VPCE:
    test_pair("S3 VPC Interface", client(VPCE_BASE))
else:
    log("S3 VPC Interface", "PUT/GET", "SKIP", details="run_vpce=false")

# COMMAND ----------
# MAGIC %md
# MAGIC ## Test 4: Negative signature test
# MAGIC Modifies the signed request's signature without printing it; a rejected request is expected. The expected 403 is a **PASS for the negative test**, not a connectivity failure.

# COMMAND ----------

if RUN_NEGATIVE:
    try:
        url = standard.generate_presigned_url(
            "get_object", Params={"Bucket": BUCKET, "Key": standard_key},
            ExpiresIn=900, HttpMethod="GET"
        )
        from urllib.parse import parse_qsl, urlencode, urlunsplit
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        mutated = [(k, ("0" * len(v) if k.lower() == "x-amz-signature" else v)) for k, v in query]
        bad_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))
        response = requests.get(bad_url, timeout=45)
        ok = response.status_code == 403
        log("Negative signature", "GET", "PASS" if ok else "FAIL",
            response.status_code, hostname(url), standard_key, "Expected HTTP 403")
    except Exception as exc:
        log("Negative signature", "GET", "FAIL", details=type(exc).__name__)
else:
    log("Negative signature", "GET", "SKIP", details="run_negative_test=false")

# COMMAND ----------
# MAGIC %md
# MAGIC ## Results / SQL evidence
# MAGIC This temp view is available to SQL cells in the same notebook session. Export the displayed results as evidence, together with the AWS team’s CloudTrail data events and VPC endpoint logs. No signed URLs are stored.

# COMMAND ----------

schema = "run_id string, timestamp_utc string, scenario string, operation string, status string, http_status long, hostname string, bucket string, object_key string, details string"
results_df = spark.createDataFrame(RESULTS, schema=schema)
results_df.createOrReplaceTempView("s3_presigned_validation_results")
display(results_df.orderBy("scenario", "operation"))

print("RUN ID:", RUN_ID)
print("All mandatory HTTP tests passed:", all(
    r["status"] == "PASS" for r in RESULTS if r["status"] != "SKIP"
))
print("Network/private routing validation: PENDING AWS LOG CORRELATION")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT run_id, timestamp_utc, scenario, operation, status,
# MAGIC        http_status, hostname, bucket, object_key, details
# MAGIC FROM s3_presigned_validation_results
# MAGIC ORDER BY scenario, operation;

# COMMAND ----------
# MAGIC %md
# MAGIC ## Evidence checklist for S3 / Network team
# MAGIC 1. Share the results table, run ID, UTC timestamps, S3 bucket and test keys, and Databricks compute/workspace type.
# MAGIC 2. Request CloudTrail **S3 data events** for test objects (must be enabled) and correlate request time and key. Ask for `vpcEndpointId` where populated.
# MAGIC 3. Ask network team for VPC interface endpoint service name, ID, status, endpoint ENI VPC Flow Logs (if enabled), and private DNS/NCC routing evidence.
# MAGIC 4. For FIPS, verify the signed hostname uses `s3-fips` and confirm the intended FIPS endpoint/service and private network route. HTTP 200 alone is insufficient.
# MAGIC 5. SQL `SELECT` on a Unity Catalog table or `DESCRIBE EXTERNAL LOCATION` is an **additional access check**, not proof of pre-signed URL use.
# MAGIC 6. Do not mark a scenario fully validated until both application results and required AWS-side evidence agree.
