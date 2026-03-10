"""
COBRA Scenario 8 infrastructure: two EC2s (victim with vulnerable app, attacker),
S3 bucket, SSM parameter, Lambda execution role for persistence demo.
"""
import base64
import json
import os
import pulumi
import pulumi_aws as aws
from pulumi_random import RandomPet

def read_public_key(pub_key_path):
    with open(pub_key_path, "r") as f:
        return f.read().strip()

# Paths relative to infra/ when running from repo root or from infra/
script_dir = os.path.dirname(os.path.abspath(__file__))
pub_key_path = os.path.join(script_dir, "..", "..", "..", "id_rsa.pub")
if not os.path.exists(pub_key_path):
    pub_key_path = os.path.join(script_dir, "..", "..", "..", "..", "id_rsa.pub")

key_pair = aws.ec2.KeyPair("my-key-pair", public_key=read_public_key(pub_key_path))

region = aws.get_region()
current = aws.get_caller_identity()

ubuntu_ami = aws.ec2.get_ami(
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name", values=["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]),
        aws.ec2.GetAmiFilterArgs(name="virtualization-type", values=["hvm"]),
    ],
    owners=["099720109477"],
    most_recent=True,
)

# Lambda execution role (for CreateFunction - victim will PassRole this)
lambda_exec_role = aws.iam.Role(
    "lambda-exec-role",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "lambda.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }]
    }""",
)
aws.iam.RolePolicyAttachment(
    "lambda-exec-policy",
    role=lambda_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# Victim EC2 role: S3 read, SSM get, Lambda create, PassRole for lambda role, AssumeRole for elevated role
victim_role = aws.iam.Role(
    "victim-role",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "ec2.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }]
    }""",
)

# Elevated role: assumable only by victim role; has SSM get and IAM CreateUser/CreateAccessKey for persistence
elevated_role = aws.iam.Role(
    "elevated-role",
    assume_role_policy=victim_role.arn.apply(
        lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": arn},
                "Action": "sts:AssumeRole",
            }],
        })
    ),
)

def elevated_role_policy_document(lambda_role_arn):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets", "s3:ListBucket", "s3:GetObject"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ssm:GetParameter", "ssm:GetParameters"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:GetFunction"], "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": lambda_role_arn},
            {
                "Effect": "Allow",
                "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy", "iam:GetUser"],
                "Resource": f"arn:aws:iam::{current.account_id}:user/cobra-s8-*",
            },
        ],
    })

aws.iam.RolePolicy(
    "elevated-role-policy",
    role=elevated_role.name,
    policy=lambda_exec_role.arn.apply(elevated_role_policy_document),
)

def victim_policy_document(elevated_role_arn):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": elevated_role_arn},
        ],
    })

victim_policy = aws.iam.RolePolicy(
    "victim-policy",
    role=victim_role.name,
    policy=elevated_role.arn.apply(victim_policy_document),
)
victim_profile = aws.iam.InstanceProfile("victim-profile", role=victim_role.name)

# Security group: SSH + web app port (8000)
sg = aws.ec2.SecurityGroup(
    "web-sg",
    ingress=[
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
        {"protocol": "tcp", "from_port": 8000, "to_port": 8000, "cidr_blocks": ["0.0.0.0/0"]},
    ],
    egress=[{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
)

# Vulnerable app content: read from file and base64 for user data
vuln_app_path = os.path.join(script_dir, "app", "vuln_app.py")
with open(vuln_app_path, "r") as f:
    vuln_app_b64 = base64.b64encode(f.read().encode()).decode()

victim_user_data = f"""#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-pip
pip3 install flask boto3
echo '{vuln_app_b64}' | base64 -d > /home/ubuntu/app.py
chown ubuntu:ubuntu /home/ubuntu/app.py
nohup python3 /home/ubuntu/app.py &
exit 0
"""

attacker_user_data = """#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl
exit 0
"""

# Victim EC2 (vulnerable web app)
victim_instance = aws.ec2.Instance(
    "victim",
    instance_type="t2.micro",
    ami=ubuntu_ami.id,
    key_name=key_pair.key_name,
    security_groups=[sg.name],
    iam_instance_profile=victim_profile.name,
    user_data=victim_user_data,
    tags={"Name": "Cobra-S8-Victim"},
)

# Attacker EC2 (no IAM)
attacker_instance = aws.ec2.Instance(
    "attacker",
    instance_type="t2.micro",
    ami=ubuntu_ami.id,
    key_name=key_pair.key_name,
    security_groups=[sg.name],
    user_data=attacker_user_data,
    tags={"Name": "Cobra-S8-Attacker"},
)

# S3 bucket + sample object
bucket_suffix = RandomPet("bucket-suffix", length=2)
bucket = aws.s3.Bucket(
    "bucket",
    bucket=bucket_suffix.id.apply(lambda s: f"cobra-s8-bucket-{s}"),
    tags={"Environment": "Dev"},
)
bucket_key = "sensitive/data.txt"
bucket_object = aws.s3.BucketObject(
    "sensitive-object",
    bucket=bucket.id,
    key=bucket_key,
    content="Sensitive data for COBRA scenario 8 demo.\n",
    content_type="text/plain",
)

# SSM Parameter (String)
ssm_param = aws.ssm.Parameter(
    "secret-param",
    name="/cobra-scenario-8/secret",
    type="String",
    value="cobra-s8-demo-secret-value",
)

# Exports
pulumi.export("Web Server Public IP", victim_instance.public_ip)
pulumi.export("Attacker Server Public IP", attacker_instance.public_ip)
pulumi.export("Web Server Instance ID", victim_instance.id)
pulumi.export("Attacker Server Instance ID", attacker_instance.id)
pulumi.export("Bucket Name", bucket.id)
pulumi.export("Bucket Key", bucket_key)
pulumi.export("SSM Parameter Name", ssm_param.name)
pulumi.export("Lambda Execution Role Arn", lambda_exec_role.arn)
pulumi.export("Elevated Role Arn", elevated_role.arn)
pulumi.export("Region", region.name)
pulumi.export("Key Pair Name", key_pair.key_name)
