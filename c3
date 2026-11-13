
import boto3
import requests
from botocore.config import Config
from urllib.parse import urlsplit

# Regional S3 FIPS endpoint
REGION = "us-east-1"
fips_endpoint = f"https://s3-fips.{REGION}.amazonaws.com"

key = f"{PREFIX}/standard-test.txt"

try:
    fips_client = boto3.client(
        "s3",
        region_name=REGION,
        endpoint_url=fips_endpoint,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"}
        )
    )

    fips_url = fips_client.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": BUCKET,
            "Key": key
        },
        ExpiresIn=900,
        HttpMethod="GET"
    )

    response = requests.get(
        fips_url,
        timeout=30
    )

    success = (
        response.status_code == 200
        and response.content == TEST_DATA
    )

    record(
        "S3 FIPS GET",
        "PASS" if success else "FAIL",
        urlsplit(fips_url).hostname,
        f"HTTP {response.status_code}; "
        f"Content verified={success}"
    )

except Exception as e:
    record(
        "S3 FIPS GET",
        "FAIL",
        fips_endpoint,
        f"{type(e).__name__}: {str(e)[:300]}"
    )
