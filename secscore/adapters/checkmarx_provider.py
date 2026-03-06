import requests
import time
from secscore.normalizers.checkmarx import normalize

MAX_WAIT = 120
POLL_INTERVAL = 5
WAIT_STATUSES = {"Queued", "Running"}
SOURCE_ORIGINS = "Azure DevOps, Bitbucket, AzurePipelines, Push Webhook, PR Webhook, Gitlab, Github Action, GitHub"

def fetch_findings(args):

    token = get_access_token(args.checkmarx_tenant, args.checkmarx_token)

    scan_id = get_latest_scan(args.checkmarx_base_url, token, args.checkmarx_project, args.branch)

    if not scan_id:
        return {"findings": []}

    raw = get_results(args.checkmarx_base_url, token, scan_id)

    return normalize(raw)

def get_access_token(tenant, refresh_token):

    url = f"https://eu.iam.checkmarx.net/auth/realms/{tenant}/protocol/openid-connect/token"

    payload = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": refresh_token
    }

    r = requests.post(url, data=payload)
    r.raise_for_status()

    return r.json()["access_token"]

def get_latest_scan(base_url, token, project, branch):
    url = f"{base_url}/api/scans"

    params = {
        "branch": branch,
        "project-names": project,
        "statuses": "Completed,Queued,Running",
        "source-origins": SOURCE_ORIGINS,
        "limit": 20
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json; version=1.0"
    }

    waited = 0

    while True:
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()

        data = r.json()

        if data.get("filteredTotalCount", 0) == 0:
            return None

        scans = data.get("scans", [])

        latest_sast_any = None
        latest_sast_completed = None

        for scan in scans:
            configs = scan.get("metadata", {}).get("configs", [])
            is_sast = any((c.get("type") or "").lower() == "sast" for c in configs)

            if not is_sast:
                continue

            if latest_sast_any is None:
                latest_sast_any = scan

            if latest_sast_completed is None and scan.get("status") == "Completed":
                latest_sast_completed = scan

            if latest_sast_any and latest_sast_completed:
                break

        if not latest_sast_any:
            raise Exception("No SAST scans found")

        latest_status = latest_sast_any.get("status")

        if latest_status == "Completed":
            return latest_sast_any["id"]

        if latest_status in WAIT_STATUSES:
            if waited >= MAX_WAIT:
                break

            print(f"SAST scan {latest_sast_any['id']} status {latest_status}, waiting...")
            time.sleep(POLL_INTERVAL)
            waited += POLL_INTERVAL
            continue

        # teoricamente não deveria cair aqui por causa do filtro de statuses,
        # mas se cair, usa fallback se existir
        if latest_sast_completed:
            return latest_sast_completed["id"]

        raise Exception("No valid completed SAST scan available")

    # timeout: usar último completed encontrado
    if latest_sast_completed:
        print(f"Timeout waiting for latest SAST scan. Falling back to completed scan {latest_sast_completed['id']}")
        return latest_sast_completed["id"]

    raise Exception("No completed SAST scan available")

def get_results(base_url, token, scan_id):

    url = f"{base_url}/api/sast-results"

    params = {
        "scan-id": scan_id,
        "include-nodes": "true",
        "apply-predicates": "true",
        "offset": 0,
        "limit": 1000
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json; version=1.0"
    }

    r = requests.get(url, headers=headers, params=params)
    r.raise_for_status()

    return r.json()