#!/usr/bin/env python3
"""
Generate production encryption keys for cloud deployment.
Run this script and store the output in your cloud platform's secret manager.
"""
import secrets
from cryptography.fernet import Fernet

def generate_keys():
    """Generate secure keys for production deployment."""
    print("🔐 Generating Production Keys for Antivirus Dashboard")
    print("=" * 60)
    
    # Generate FERNET_KEY
    fernet_key = Fernet.generate_key().decode()
    print(f"\n📝 FERNET_KEY (44 chars):")
    print(f"   {fernet_key}")
    print(f"   Length: {len(fernet_key)} characters")
    
    # Generate FLASK_SECRET_KEY
    flask_secret = secrets.token_hex(32)
    print(f"\n📝 FLASK_SECRET_KEY (64 chars):")
    print(f"   {flask_secret}")
    print(f"   Length: {len(flask_secret)} characters")
    
    # Generate additional secure random values
    api_key = secrets.token_urlsafe(32)
    print(f"\n📝 Optional API_KEY (43 chars):")
    print(f"   {api_key}")
    
    print("\n" + "=" * 60)
    print("🚀 Deployment Instructions:")
    print("=" * 60)
    print("\n1. Store these keys in your cloud platform's secret manager:")
    print("   - AWS Secrets Manager: Create secrets 'FERNET_KEY' and 'FLASK_SECRET_KEY'")
    print("   - Azure Key Vault: Add secrets to your key vault")
    print("   - Google Secret Manager: Create secrets in your project")
    print("   - Environment Variables: Set in your hosting platform dashboard")
    
    print("\n2. For simple deployment, set as environment variables:")
    print("   export FERNET_KEY='your-fernet-key'")
    print("   export FLASK_SECRET_KEY='your-flask-secret'")
    print("   export FLASK_ENV='production'")
    
    print("\n3. NEVER commit these keys to git or store in .env files!")
    print("   These keys are for ONE deployment only.")
    
    print("\n4. Backup these keys securely in case you need to:")
    print("   - Restore your deployment")
    print("   - Migrate to another platform")
    print("   - Recover from disaster")
    
    print("\n" + "=" * 60)
    print("✅ Keys generated successfully!")
    print("=" * 60)

if __name__ == "__main__":
    generate_keys()