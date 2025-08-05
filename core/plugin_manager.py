"""
Plugin Manager for Naswail SIEM Tool
----------------------------------
Handles the discovery, loading, and lifecycle management of plugins.
"""

import os
import importlib
import inspect
from typing import Dict, Type, List, Any
from abc import ABC

class PluginManager:
    """
    Manages the lifecycle of plugins in the Naswail SIEM Tool.
    
    This class is responsible for:
    - Discovering plugins in designated directories
    - Loading and initializing plugins with their dependencies
    - Managing plugin state and configuration
    - Providing access to loaded plugins
    """
    
    def __init__(self, plugin_dirs: List[str] = None):
        """
        Initialize the plugin manager.
        
        Args:
            plugin_dirs: List of directories to search for plugins.
                        Defaults to ['plugins/analysis', 'plugins/response', 
                                   'plugins/tools', 'plugins/home']
        """
        self.plugin_dirs = plugin_dirs or [
            'plugins/analysis',
            'plugins/response',
            'plugins/tools',
            'plugins/home'
        ]
        # Store loaded plugin instances by their unique identifiers
        self._plugins: Dict[str, Any] = {}
        # Store plugin class definitions
        self._plugin_classes: Dict[str, Type] = {}
        
    def discover_plugins(self) -> None:
        """
        Scan plugin directories and discover available plugins.
        
        This method:
        1. Walks through plugin directories
        2. Identifies Python modules
        3. Loads and registers plugin classes
        """
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                os.makedirs(plugin_dir)
                
            # Walk through the plugin directory
            for root, _, files in os.walk(plugin_dir):
                for file in files:
                    if file.endswith('.py') and not file.startswith('__'):
                        # Convert file path to module path
                        rel_path = os.path.relpath(root, '.')
                        module_path = os.path.join(rel_path, file[:-3]).replace(os.sep, '.')
                        
                        try:
                            # Import the module
                            module = importlib.import_module(module_path)
                            
                            # Find plugin classes in the module
                            for name, obj in inspect.getmembers(module):
                                if (inspect.isclass(obj) and 
                                    issubclass(obj, ABC) and 
                                    obj != ABC):
                                    plugin_id = f"{module_path}.{name}"
                                    self._plugin_classes[plugin_id] = obj
                                    
                        except Exception as e:
                            print(f"Error loading plugin from {module_path}: {e}")
    
    def initialize_plugin(self, plugin_id: str, **kwargs) -> Any:
        """
        Initialize a specific plugin with dependencies.
        
        Args:
            plugin_id: Unique identifier of the plugin to initialize
            **kwargs: Dependencies to inject into the plugin
            
        Returns:
            Initialized plugin instance
        """
        if plugin_id not in self._plugin_classes:
            raise KeyError(f"Plugin {plugin_id} not found")
            
        plugin_class = self._plugin_classes[plugin_id]
        plugin = plugin_class(**kwargs)
        self._plugins[plugin_id] = plugin
        return plugin
    
    def get_plugin(self, plugin_id: str) -> Any:
        """
        Get an initialized plugin instance.
        
        Args:
            plugin_id: Unique identifier of the plugin
            
        Returns:
            Plugin instance if found
        """
        return self._plugins.get(plugin_id)
    
    def get_all_plugins(self) -> Dict[str, Any]:
        """
        Get all initialized plugins.
        
        Returns:
            Dictionary of plugin_id -> plugin_instance
        """
        return self._plugins.copy()
    
    def unload_plugin(self, plugin_id: str) -> None:
        """
        Unload and cleanup a plugin.
        
        Args:
            plugin_id: Unique identifier of the plugin to unload
        """
        if plugin_id in self._plugins:
            # Call cleanup method if it exists
            plugin = self._plugins[plugin_id]
            if hasattr(plugin, 'cleanup'):
                plugin.cleanup()
            del self._plugins[plugin_id] 