"""
Naswail SIEM Tool - Core Package
-------------------------------
This package provides the core framework for the Naswail SIEM Tool,
including plugin management, dependency injection, and shared interfaces.
"""

__version__ = '1.0.0'

# These will be populated as we create the other core modules
from .plugin_manager import PluginManager 