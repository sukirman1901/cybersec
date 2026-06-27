import json
import shutil
import asyncio


async def cloud_iam_audit(provider: str = "aws") -> dict:
    """Audit cloud IAM policies — overly permissive roles, public access, cross-account trust."""
    if provider == "aws":
        prowler_path = shutil.which("prowler")
        if prowler_path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "prowler", "aws", "--services", "iam", "-M", "json",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                output = stdout.decode(errors="replace").strip()

                findings = []
                for line in output.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            findings.append({"raw": line})

                return {"provider": "aws", "tool": "prowler", "findings": findings, "count": len(findings)}
            except asyncio.TimeoutError:
                return {"provider": "aws", "tool": "prowler", "error": "prowler scan timed out"}
            except Exception as e:
                return {"provider": "aws", "tool": "prowler", "error": f"Failed to run prowler: {str(e)}"}

        aws_path = shutil.which("aws")
        if aws_path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "aws", "iam", "list-roles", "--output", "json",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
                output = stdout.decode(errors="replace").strip()

                try:
                    data = json.loads(output)
                    roles = data.get("Roles", [])
                except json.JSONDecodeError:
                    roles = []

                return {"provider": "aws", "tool": "aws-cli", "roles": roles, "count": len(roles)}
            except asyncio.TimeoutError:
                return {"provider": "aws", "tool": "aws-cli", "error": "aws iam command timed out"}
            except Exception as e:
                return {"provider": "aws", "tool": "aws-cli", "error": f"Failed to run aws: {str(e)}"}

        return {"provider": "aws", "error": "Neither prowler nor aws CLI found in PATH"}

    elif provider == "gcp":
        gcloud_path = shutil.which("gcloud")
        if not gcloud_path:
            return {"provider": "gcp", "error": "gcloud CLI not found in PATH"}

        try:
            proc = await asyncio.create_subprocess_exec(
                "gcloud", "iam", "roles", "list",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode(errors="replace").strip()

            findings = []
            for line in output.split("\n"):
                line = line.strip()
                if line:
                    findings.append(line)

            return {"provider": "gcp", "tool": "gcloud", "roles": findings, "count": len(findings)}
        except asyncio.TimeoutError:
            return {"provider": "gcp", "error": "gcloud command timed out"}
        except Exception as e:
            return {"provider": "gcp", "error": f"Failed to run gcloud: {str(e)}"}

    else:
        return {"error": f"Unsupported provider: {provider}", "supported_providers": ["aws", "gcp"]}
