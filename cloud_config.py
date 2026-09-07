"""
Cloud-compatible configuration loader for production deployment.
Supports multiple secret management backends.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def get_cloud_secret(secret_name: str, default: Optional[str] = None) -> str:
    """
    Get a secret from cloud secret management services with fallbacks.
    
    Priority order:
    1. Environment variables (most common for cloud deployment)
    2. AWS Secrets Manager
    3. Azure Key Vault
    4. Google Secret Manager
    5. Default value (if provided)
    
    Args:
        secret_name: Name of the secret to retrieve
        default: Optional default value if secret not found
    
    Returns:
        The secret value or raises ValueError if not found
    """
    # Priority 1: Environment variables (most common for cloud deployment)
    env_value = os.environ.get(secret_name)
    if env_value:
        logger.debug(f"Loaded {secret_name} from environment variables")
        return env_value
    
    # Priority 2: AWS Secrets Manager
    try:
        import boto3
        client = boto3.client('secretsmanager', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
        try:
            response = client.get_secret_value(SecretId=secret_name)
            secret = response['SecretString']
            logger.debug(f"Loaded {secret_name} from AWS Secrets Manager")
            return secret
        except Exception as e:
            logger.debug(f"AWS Secrets Manager lookup failed: {e}")
    except ImportError:
        logger.debug("boto3 not available, skipping AWS Secrets Manager")
    
    # Priority 3: Azure Key Vault
    try:
        from azure.keyvault.secrets import SecretClient
        from azure.identity import DefaultAzureCredential
        
        vault_url = os.environ.get('AZURE_KEY_VAULT_URL')
        if vault_url:
            client = SecretClient(
                vault_url=vault_url, 
                credential=DefaultAzureCredential()
            )
            secret = client.get_secret(secret_name).value
            logger.debug(f"Loaded {secret_name} from Azure Key Vault")
            return secret
    except ImportError:
        logger.debug("azure libraries not available, skipping Azure Key Vault")
    except Exception as e:
        logger.debug(f"Azure Key Vault lookup failed: {e}")
    
    # Priority 4: Google Secret Manager
    try:
        from google.cloud import secretmanager
        
        project_id = os.environ.get('GOOGLE_PROJECT_ID')
        if project_id:
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
            response = client.access_secret_version(request={"name": name})
            secret = response.payload.data.decode()
            logger.debug(f"Loaded {secret_name} from Google Secret Manager")
            return secret
    except ImportError:
        logger.debug("google-cloud-secret-manager not available, skipping Google Secret Manager")
    except Exception as e:
        logger.debug(f"Google Secret Manager lookup failed: {e}")
    
    # Priority 5: Default value or raise error
    if default is not None:
        logger.warning(f"Using default value for {secret_name}")
        return default
    
    raise ValueError(
        f"Secret {secret_name} not found in any secret management backend. "
        "Please set it as an environment variable or configure a secret manager."
    )

def get_production_config():
    """
    Load production configuration from cloud secrets.
    
    Returns:
        Dictionary with all required configuration values
    """
    try:
        config = {
            'FERNET_KEY': get_cloud_secret('FERNET_KEY'),
            'FLASK_SECRET_KEY': get_cloud_secret('FLASK_SECRET_KEY'),
            'FLASK_ENV': get_cloud_secret('FLASK_ENV', 'production'),
            'DATABASE_URL': get_cloud_secret('DATABASE_URL', ''),
            'REDIS_URL': get_cloud_secret('REDIS_URL', ''),
            'MALWAREBAZAAR_API_KEY': get_cloud_secret('MALWAREBAZAAR_API_KEY', ''),
            'VT_API_KEY': get_cloud_secret('VT_API_KEY', ''),
            'HTTPBL_API_KEY': get_cloud_secret('HTTPBL_API_KEY', ''),
        }
        
        # Validate required secrets
        if not config['FERNET_KEY'] or len(config['FERNET_KEY']) != 44:
            raise ValueError("FERNET_KEY must be a 44-character base64 string")
        
        if not config['FLASK_SECRET_KEY']:
            raise ValueError("FLASK_SECRET_KEY is required")
        
        logger.info("Successfully loaded production configuration from cloud secrets")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load production configuration: {e}")
        raise

# Example usage for your cloud server
if __name__ == "__main__":
    # Test the configuration loader
    try:
        config = get_production_config()
        print("Configuration loaded successfully!")
        print(f"Environment: {config['FLASK_ENV']}")
        print(f"FERNET_KEY length: {len(config['FERNET_KEY'])}")
        print(f"FLASK_SECRET_KEY length: {len(config['FLASK_SECRET_KEY'])}")
    except Exception as e:
        print(f"Configuration loading failed: {e}")
        print("\nTo fix this, set environment variables:")
        print("export FERNET_KEY='your-fernet-key'")
        print("export FLASK_SECRET_KEY='your-secret-key'")
        print("export FLASK_ENV='production'")