# Load environment variables from .env file
load_dotenv()

class GitHubClient:
    """
    GitHubClient for API access with a single personal access token (PAT).
    """

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GITHUB_TOKEN not found in environment variables.")
        self.client = Github(self.token)

    def get_user(self):
        """Return the authenticated user"""
        return self.client.get_user()

    def list_repos(self):
        """List all repositories for the authenticated user"""
        user = self.get_user()
        return list(user.get_repos())