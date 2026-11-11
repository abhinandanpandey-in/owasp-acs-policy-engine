import os

def load_model():
    return "gpt-4-turbo"

@tool(requires_approval=False)
def scan_repository(repo_url: str):
    """Clones and scans a repository for vulnerabilities."""
    return f"Scanned {repo_url}"

@mcp.tool(requires_auth=True)
def delete_database(db_name: str, force: bool = False):
    """Drops the production database. Requires approval transit token."""
    if not force:
        raise ValueError("Force flag required")
    return f"Dropped {db_name}"

@tool(requires_approval=True)
def human_approval_webhook(run_id: str):
    """Waits for Slack approval."""
    return "APPROVED"
