from pathlib import Path

from git import Repo


def clone_or_pull(repo_dir: Path, repo_url: str, branch: str = "main") -> Repo:
    repo_dir.mkdir(parents=True, exist_ok=True)
    repo_path = repo_dir / "zone-repo"

    if repo_path.exists():
        repo = Repo(repo_path)
        origin = repo.remotes.origin
        origin.pull(rebase=True)
    else:
        repo = Repo.clone_from(repo_url, repo_path, branch=branch)

    return repo


def commit_and_push(repo_dir: Path, message: str) -> None:
    repo_path = repo_dir / "zone-repo"
    repo = Repo(repo_path)

    if repo.is_dirty(untracked_files=True):
        repo.index.add("*")
        repo.index.commit(message)
        origin = repo.remotes.origin
        origin.push()
