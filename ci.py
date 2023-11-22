import os
import requests
import uuid

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



DEFAULT_MD = """| Project Name | Vulnerability Found | Time Taken | Log |
|---------|---------|---------|---------|"""

def parse_res(file):
    with open(UID + "/" + file, 'r') as f:
        lines = f.readlines()
        last_ts = -1
        ts = -1
        violation = ""
        crashed = False
        for i in lines:
            if "run time: " in i:
                _ts = i.split("run time: ")[1].split(",")[0]
                last_ts = _ts
            if "Anyone can earn" in i:
                ts = last_ts
                violation = "Fund Loss"
            if "reserves has changed from " in i:
                ts = last_ts
                violation = "Price Manipulation"
            if "Arbitrary call " in i:
                ts = last_ts
                violation = "Arbitrary Call"
            if "panicked at " in i:
                crashed = True
        violation = "✅ " + violation  if violation else "❌"

        if crashed:
            violation = "❌‼️  Crashed"

        return (file.replace("res_", ""), ts, violation)


UID = str(uuid.uuid4())

def parse_all():
    os.system(f"mkdir {UID} && mv res_* {UID} && aws s3 cp {UID} s3://cilogs-ityfuzz/{UID} --recursive")

    found = 0
    md = DEFAULT_MD
    for i in os.listdir(UID):
        if i.startswith("res_"):
            fn, ts, violation = parse_res(i)
            if "❌" not in violation:
                found += 1
            log = f"https://cilogs-ityfuzz.s3.amazonaws.com/{UID}/{i}"
            md += f"\n| {fn} | {violation} | {ts} | [Log File]({log}) |"
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



