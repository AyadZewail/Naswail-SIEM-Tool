import pytest
from unittest.mock import MagicMock

from controllers.IncidentResponse_Controller import IncidentResponseController

# 1. This is our STUB. It doesn't verify anything, it just returns predetermined data.
class StubAutopilotEngine:
    def __init__(self, action_to_return, log_to_return):
        self.action_to_return = action_to_return
        self.log_to_return = log_to_return
        
    def decide(self, prompt: str):
        # We completely ignore the prompt and return our hardcoded decision
        return self.action_to_return, self.log_to_return

@pytest.fixture
def controller_factory():
    """
    Returns a factory function so we can create controllers with different
    stubs and mocks for each test.
    """
    def _create_controller(stub_autopilot, mock_mitigation_engine):
        # We use MagicMock for all the GUI/State dependencies because we don't 
        # care about them for this specific integration boundary.
        return IncidentResponseController(
            ui=MagicMock(),
            anomalies=[],
            protocol_extractor=MagicMock(),
            autopilot_engine=stub_autopilot,
            threat_intel=MagicMock(),
            blacklist=[],
            blocked_ports=[],
            network_log=[],
            mitigation_engine=mock_mitigation_engine,
            autopilot_log=MagicMock(),
            main_window=MagicMock()
        )
    return _create_controller

def test_autopilot_to_block_ip_integration(controller_factory):
    # Arrange
    # The Stub: Dictates what the Autopilot will say
    stub_autopilot = StubAutopilotEngine(action_to_return="block_ip", log_to_return="Threat severe.")
    # The Mock: Records what happens to the Mitigation Engine
    mock_mitigation = MagicMock()
    
    controller = controller_factory(stub_autopilot, mock_mitigation)
    
    test_ip = "192.168.1.50"
    test_port = 80
    
    # Act
    # We simulate the end of the extraction pipeline where mitigate() is called
    controller.mitigate(prompt="Block this attacker", ip=test_ip, port=test_port, scrapetime=1.5)
    
    # Assert
    # We verify that the controller correctly translated the string "block_ip" 
    # into a method call `block_ip()` on the mitigation engine, passing the IP.
    mock_mitigation.block_ip.assert_called_once_with(test_ip)
    
    # Ensure it didn't accidentally call other things
    mock_mitigation.block_port.assert_not_called()
    mock_mitigation.limit_rate.assert_not_called()

def test_autopilot_to_limit_rate_integration(controller_factory):
    # Arrange
    stub_autopilot = StubAutopilotEngine(action_to_return="limit_rate", log_to_return="DDoS suspected.")
    mock_mitigation = MagicMock()
    controller = controller_factory(stub_autopilot, mock_mitigation)
    test_ip = "10.0.0.5"
    
    # Act
    controller.mitigate(prompt="Limit this IP", ip=test_ip, port=443, scrapetime=0.5)
    
    # Assert
    # The mitigate function hardcodes "8" as the rate limit in its implementation:
    # elif action == "limit_rate": args = [ip, "8"]
    mock_mitigation.limit_rate.assert_called_once_with(test_ip, "8")

def test_autopilot_to_block_port_integration(controller_factory):
    # Arrange
    stub_autopilot = StubAutopilotEngine(action_to_return="block_port", log_to_return="Port scan detected.")
    mock_mitigation = MagicMock()
    controller = controller_factory(stub_autopilot, mock_mitigation)
    test_port = 22
    
    # Act
    controller.mitigate(prompt="Block ssh port", ip="1.1.1.1", port=test_port, scrapetime=0.1)
    
    # Assert
    mock_mitigation.block_port.assert_called_once_with(test_port)

def test_autopilot_unknown_action_handled_gracefully(controller_factory):
    # Arrange
    # What happens if the LLM hallucinates an action that doesn't exist?
    stub_autopilot = StubAutopilotEngine(action_to_return="launch_nukes", log_to_return="Extremis.")
    mock_mitigation = MagicMock()
    controller = controller_factory(stub_autopilot, mock_mitigation)
    
    # Act
    # This shouldn't crash the application
    controller.mitigate(prompt="Do something", ip="1.1.1.1", port=80, scrapetime=0.1)
    
    # Assert
    # The mitigation engine should not have been called at all
    mock_mitigation.block_ip.assert_not_called()
    mock_mitigation.block_port.assert_not_called()
    mock_mitigation.limit_rate.assert_not_called()
