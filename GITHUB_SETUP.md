# Push this PoC to GitHub

The repo is already initialized with an initial commit on `main`.

## Option A — New GitHub repo (recommended)

1. Create a new **empty** repository on GitHub (no README, no .gitignore).
2. From this folder:

```bash
cd poc
git remote add origin https://github.com/<YOUR_ORG>/<YOUR_REPO>.git
git push -u origin main
```

## Option B — GitHub CLI

```bash
cd poc
gh repo create ai-multicloud-compliance-poc --private --source=. --remote=origin --push
```

## After push

Share the repo URL so stakeholders can clone and run:

```bash
git clone https://github.com/<YOUR_ORG>/<YOUR_REPO>.git
cd <YOUR_REPO>
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Dashboard: http://localhost:8000
