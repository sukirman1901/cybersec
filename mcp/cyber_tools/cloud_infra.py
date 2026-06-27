import json
import shutil
import asyncio


async def cloud_infra(provider: str = "aws", service: str = "ec2") -> dict:
    """Enumerate cloud infra config — open security groups, unencrypted storage, public endpoints."""
    if provider == "aws":
        if service == "ec2":
            scout_path = shutil.which("scoutsuite")
            if scout_path:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "scoutsuite", "aws", "--services", "ec2",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                    output = stdout.decode(errors="replace").strip()
                    return {"provider": "aws", "service": "ec2", "tool": "scoutsuite", "output": output or stderr.decode(errors="replace").strip()}
                except asyncio.TimeoutError:
                    return {"provider": "aws", "service": "ec2", "tool": "scoutsuite", "error": "scoutsuite scan timed out"}
                except Exception as e:
                    return {"provider": "aws", "service": "ec2", "tool": "scoutsuite", "error": f"Failed to run scoutsuite: {str(e)}"}

            aws_path = shutil.which("aws")
            if aws_path:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "aws", "ec2", "describe-security-groups",
                        "--query", "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]",
                        "--output", "json",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
                    output = stdout.decode(errors="replace").strip()

                    try:
                        sgs = json.loads(output)
                    except json.JSONDecodeError:
                        sgs = []

                    return {"provider": "aws", "service": "ec2", "tool": "aws-cli", "open_security_groups": sgs, "count": len(sgs)}
                except asyncio.TimeoutError:
                    return {"provider": "aws", "service": "ec2", "tool": "aws-cli", "error": "aws ec2 command timed out"}
                except Exception as e:
                    return {"provider": "aws", "service": "ec2", "tool": "aws-cli", "error": f"Failed to run aws: {str(e)}"}

            return {"provider": "aws", "service": "ec2", "error": "Neither scoutsuite nor aws CLI found in PATH"}

        elif service == "s3":
            aws_path = shutil.which("aws")
            if not aws_path:
                return {"provider": "aws", "service": "s3", "error": "aws CLI not found in PATH"}

            try:
                proc = await asyncio.create_subprocess_exec(
                    "aws", "s3api", "list-buckets", "--output", "json",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
                output = stdout.decode(errors="replace").strip()

                try:
                    data = json.loads(output)
                    buckets = data.get("Buckets", [])
                except json.JSONDecodeError:
                    buckets = []

                return {"provider": "aws", "service": "s3", "buckets": buckets, "count": len(buckets)}
            except asyncio.TimeoutError:
                return {"provider": "aws", "service": "s3", "error": "aws s3 command timed out"}
            except Exception as e:
                return {"provider": "aws", "service": "s3", "error": f"Failed to run aws: {str(e)}"}

        else:
            return {"error": f"Unsupported AWS service: {service}", "supported_services": ["ec2", "s3"]}

    elif provider == "azure":
        az_path = shutil.which("az")
        if not az_path:
            return {"provider": "azure", "error": "az CLI not found in PATH"}

        try:
            proc = await asyncio.create_subprocess_exec(
                "az", "vm", "list", "--output", "json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode(errors="replace").strip()

            try:
                vms = json.loads(output)
            except json.JSONDecodeError:
                vms = []

            return {"provider": "azure", "service": "vm", "virtual_machines": vms, "count": len(vms)}
        except asyncio.TimeoutError:
            return {"provider": "azure", "error": "az vm list command timed out"}
        except Exception as e:
            return {"provider": "azure", "error": f"Failed to run az: {str(e)}"}

    else:
        return {"error": f"Unsupported provider: {provider}", "supported_providers": ["aws", "azure"]}
