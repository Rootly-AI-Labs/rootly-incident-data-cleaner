"""
LLM Configuration for PII Pipeline
Supports OpenAI GPT-4o and Anthropic Claude-3.5-Sonnet
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"

@dataclass
class LLMModel:
    """LLM model configuration"""
    provider: LLMProvider
    model_name: str
    api_key_env_var: str
    max_tokens: int = 1000
    temperature: float = 0.1
    timeout: int = 30

@dataclass
class LLMConfig:
    """Complete LLM configuration"""
    finder_model: LLMModel
    judge_model: LLMModel
    fallback_model: LLMModel
    enable_real_api: bool = False
    api_timeout: int = 30
    retry_attempts: int = 3

class LLMConfigManager:
    """Manages LLM configuration and API setup"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config/llm_models.json"
        self.config = self._load_default_config()
        
        if config_file:
            self.load_from_file(config_file)
    
    def _load_default_config(self) -> LLMConfig:
        """Load default configuration"""
        return LLMConfig(
            finder_model=LLMModel(
                provider=LLMProvider.OPENAI,
                model_name="gpt-4o",
                api_key_env_var="OPENAI_API_KEY",
                max_tokens=2000,
                temperature=0.1
            ),
            judge_model=LLMModel(
                provider=LLMProvider.ANTHROPIC,
                model_name="claude-3-5-sonnet-20241022",
                api_key_env_var="ANTHROPIC_API_KEY",
                max_tokens=1500,
                temperature=0.05
            ),
            fallback_model=LLMModel(
                provider=LLMProvider.OPENAI,
                model_name="gpt-4o-mini",
                api_key_env_var="OPENAI_API_KEY",
                max_tokens=256,
                temperature=0.2
            )
        )
    
    def load_from_file(self, filepath: str):
        """Load configuration from JSON file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Parse models
            finder_data = data['finder_model']
            judge_data = data['judge_model']
            fallback_data = data['fallback_model']
            
            self.config.finder_model = LLMModel(**finder_data)
            self.config.judge_model = LLMModel(**judge_data)
            self.config.fallback_model = LLMModel(**fallback_data)
            self.config.enable_real_api = data.get('enable_real_api', False)
            
            logger.info(f"LLM configuration loaded from {filepath}")
            
        except Exception as e:
            logger.warning(f"Failed to load LLM config from {filepath}: {e}")
            logger.info("Using default configuration")
    
    def save_to_file(self, filepath: str):
        """Save configuration to JSON file"""
        data = {
            'finder_model': asdict(self.config.finder_model),
            'judge_model': asdict(self.config.judge_model),
            'fallback_model': asdict(self.config.fallback_model),
            'enable_real_api': self.config.enable_real_api,
            'api_timeout': self.config.api_timeout,
            'retry_attempts': self.config.retry_attempts
        }
        
        # Convert enums to strings
        for model in ['finder_model', 'judge_model', 'fallback_model']:
            data[model]['provider'] = data[model]['provider'].value
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"LLM configuration saved to {filepath}")
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate that required API keys are available"""
        validation = {}
        
        models = {
            'finder': self.config.finder_model,
            'judge': self.config.judge_model,
            'fallback': self.config.fallback_model
        }
        
        for name, model in models.items():
            api_key = os.getenv(model.api_key_env_var)
            validation[name] = api_key is not None and len(api_key.strip()) > 0
        
        return validation
    
    def get_api_key(self, model_name: str) -> Optional[str]:
        """Get API key for model"""
        model_map = {
            'finder': self.config.finder_model,
            'judge': self.config.judge_model,
            'fallback': self.config.fallback_model
        }
        
        model = model_map.get(model_name, self.config.fallback_model)
        return os.getenv(model.api_key_env_var)
    
    def set_api_keys(self, openai_key: str = None, anthropic_key: str = None):
        """Set API keys in environment"""
        if openai_key:
            os.environ[self.config.finder_model.api_key_env_var] = openai_key
            os.environ[self.config.fallback_model.api_key_env_var] = openai_key
            logger.info("OpenAI API key set")
        
        if anthropic_key:
            os.environ[self.config.judge_model.api_key_env_var] = anthropic_key
            logger.info("Anthropic API key set")

# Default instance
config_manager = LLMConfigManager()

# Export for easy access
def get_config() -> LLMConfig:
    return config_manager.config

def get_api_key(model_name: str) -> Optional[str]:
    return config_manager.get_api_key(model_name)

def validate_keys() -> Dict[str, bool]:
    return config_manager.validate_api_keys()

def setup_api_keys(openai_key: str = None, anthropic_key: str = None):
    config_manager.set_api_keys(openai_key, anthropic_key)
