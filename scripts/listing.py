"""What a listing pull request may touch, shared by the check and the merge gate."""

# The only files a listing pull request may change.
LISTING_FILES = ("index.json",)
# Pull requests from these author associations are reviewed by hand, never merged by a bot.
MAINTAINER_ROLES = ("OWNER", "MEMBER", "COLLABORATOR")
# Who maintains the directory: the users named in this file, plus the roles above.
CODEOWNERS = ".github/CODEOWNERS"


def code_owners(text: str) -> set[str]:
    """Lowercased user logins named in a CODEOWNERS file (teams are skipped)."""
    owners = set()
    for line in text.splitlines():
        for word in line.split("#", 1)[0].split()[1:]:
            if word.startswith("@") and "/" not in word:
                owners.add(word[1:].lower())
    return owners


def is_maintainer(login: str, association: str, owners: set[str]) -> bool:
    # A private organization member is reported as CONTRIBUTOR, so the role
    # alone does not identify every maintainer.
    return association in MAINTAINER_ROLES or login.lower() in owners
