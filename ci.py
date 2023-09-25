import os
import requests

def post_comment_to_pr(pr_number, token, message):
    """
    Post a comment to a GitHub PR.
    
    Parameters:
        pr_number (int): The PR number.
        token (str): The GitHub token to authenticate with.
        message (str): The comment message.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "User-Agent": "PR-Commenter",
        "Accept": "application/vnd.github.v3+json",
    }
    data = {"body": message}
    
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code == 201:
        print("Successfully posted the comment!")
    else:
        print(f"Failed to post comment. Status code: {response.status_code}, Response: {response.text}")



DEFAULT_MD = """| Project Name | Vulnerability Found | Time Taken |
|---------|---------|---------|"""

def parse_res(file):
    with open(file, 'r') as f:
        lines = f.readlines()
        last_ts = -1
        ts = -1
        violation = ""
        for i in lines:
            if "run time: " in i:
                _ts = i.split("run time: ")[1].split(",")[0]
                last_ts = _ts
            if "more than owed" in i:
                ts = last_ts
                violation = "erc20"
            if "Reserves changed from" in i:
                ts = last_ts
                violation = "uniswapv2"
        return (file.replace("res_", ""), ts, "✅" + violation  if violation else "❌")


def parse_all():
    found = 0
    md = DEFAULT_MD
    for i in os.listdir("."):
        if i.startswith("res_"):
            fn, ts, violation = parse_res(i)
            if violation != "❌":
                found += 1
            md += f"\n| {fn} | {violation} | {ts} |"
    return f"Found: {found}\n\n" + md

if __name__ == "__main__":
    PR_NUMBER = os.environ.get("PR_NUMBER")
    GITHUB_TOKEN = os.environ.get("BOT_GH_TOKEN")
    owner = "fuzzland"
    repo = "ityfuzz"

    comment_message = parse_all()
    print(comment_message)
    if not PR_NUMBER or not GITHUB_TOKEN:
        print("Missing PR_NUMBER or GITHUB_TOKEN environment variables!")
        exit(1)


    post_comment_to_pr(PR_NUMBER, GITHUB_TOKEN, comment_message)



