"""What a listing pull request may touch, shared by the check and the merge gate."""

# The only files a listing pull request may change.
LISTING_FILES = ("index.json", "README.md")
# Pull requests from these author associations are reviewed by hand, never merged by a bot.
MAINTAINER_ROLES = ("OWNER", "MEMBER", "COLLABORATOR")
