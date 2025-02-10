import textwrap
import logging

from unittest import mock
from unittest.mock import mock_open

import pytest

from logitech_receiver import diversion
from logitech_receiver.base import HIDPPNotification
from logitech_receiver.hidpp20_constants import SupportedFeature
from logitech_receiver.special_keys import CONTROL


@pytest.fixture
def rule_config():
    rule_content = """
    %YAML 1.3
    ---
    - MouseGesture: Mouse Left
    - KeyPress:
      - [Control_L, Alt_L, Left]
      - click
    ...
    ---
    - MouseGesture: Mouse Up
    - KeyPress:
      - [Super_L, Up]
      - click
    ...
    ---
    - Test: [thumb_wheel_up, 10]
    - KeyPress:
      - [Control_L, Page_Down]
      - click
    ...
    ---
    """
    return textwrap.dedent(rule_content)


def test_load_rule_config(rule_config):
    expected_rules = [
        [
            diversion.MouseGesture,
            diversion.KeyPress,
        ],
        [diversion.MouseGesture, diversion.KeyPress],
        [diversion.Test, diversion.KeyPress],
    ]

    with mock.patch("builtins.open", new=mock_open(read_data=rule_config)):
        loaded_rules = diversion._load_rule_config(file_path=mock.Mock())

    assert len(loaded_rules.components) == 2  # predefined and user configured rules
    user_configured_rules = loaded_rules.components[0]
    assert isinstance(user_configured_rules, diversion.Rule)

    for components, expected_components in zip(user_configured_rules.components, expected_rules):
        for component, expected_component in zip(components.components, expected_components):
            assert isinstance(component, expected_component)


def test_diversion_rule():
    args = [
        {
            "Rule": [  # Implement problematic keys for Craft and MX Master
                {"Rule": [{"Key": ["Brightness Down", "pressed"]}, {"KeyPress": "XF86_MonBrightnessDown"}]},
                {"Rule": [{"Key": ["Brightness Up", "pressed"]}, {"KeyPress": "XF86_MonBrightnessUp"}]},
            ]
        },
    ]

    rule = diversion.Rule(args)

    assert len(rule.components) == 1
    root_rule = rule.components[0]
    assert isinstance(root_rule, diversion.Rule)

    assert len(root_rule.components) == 2
    for component in root_rule.components:
        assert isinstance(component, diversion.Rule)
        assert len(component.components) == 2

        key = component.components[0]
        assert isinstance(key, diversion.Key)
        key = component.components[1]
        assert isinstance(key, diversion.KeyPress)


def test_key_is_down():
    result = diversion.key_is_down(key=diversion.CONTROL.G2)

    assert result is False


def test_feature():
    expected_data = {"Feature": "CONFIG CHANGE"}

    result = diversion.Feature("CONFIG_CHANGE")

    assert result.data() == expected_data


@pytest.mark.parametrize(
    "feature, data",
    [
        (
            SupportedFeature.REPROG_CONTROLS_V4,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ),
        (SupportedFeature.GKEY, [0x01, 0x02, 0x03, 0x04]),
        (SupportedFeature.MKEYS, [0x01, 0x02, 0x03, 0x04]),
        (SupportedFeature.MR, [0x01, 0x02, 0x03, 0x04]),
        (SupportedFeature.THUMB_WHEEL, [0x01, 0x02, 0x03, 0x04, 0x05]),
        (SupportedFeature.DEVICE_UNIT_ID, [0x01, 0x02, 0x03, 0x04, 0x05]),
    ],
)
def test_process_notification(feature, data):
    device_mock = mock.Mock()
    notification = HIDPPNotification(
        report_id=0x01,
        devnumber=1,
        sub_id=0x13,
        address=0x00,
        data=bytes(data),
    )

    diversion.process_notification(device_mock, notification, feature)


@pytest.mark.parametrize(
    "args, expected_key, expected_action",
    [
        # Test single string argument (defaults to "pressed" action)
        ("Calculator", CONTROL["Calculator"], "pressed"),
        
        # Test empty list
        ([], 0, "pressed"),
        
        # Test list with single key (defaults to "pressed" action) 
        (["Calculator"], CONTROL["Calculator"], "pressed"),
        
        # Test list with key and action
        (["Calculator", "pressed"], CONTROL["Calculator"], "pressed"),
        (["Calculator", "released"], CONTROL["Calculator"], "released"),
        
        # Test invalid key name (should set key to 0)
        ("InvalidKey", 0, "pressed"),
        
        # Test invalid action (should default to "pressed")
        (["Calculator", "invalid"], CONTROL["Calculator"], "pressed"),
        
        # Test invalid input types
        (123, 0, "pressed"),  # Non-string/list input
        (None, 0, "pressed"),  # None input
    ]
)
def test_key_initialization(args, expected_key, expected_action):
    """Test Key class initialization with various arguments"""
    key = diversion.Key(args, warn=False)
    assert key.key == expected_key
    assert key.action == expected_action

@pytest.mark.parametrize(
    "key_name, key_action, key_down, key_up, expected_result",
    [
        # Test key press detection
        ("Calculator", "pressed", CONTROL["Calculator"], None, True),
        ("Calculator", "pressed", None, CONTROL["Calculator"], False),
        ("Calculator", "pressed", CONTROL["Menu"], None, False),
        
        # Test key release detection
        ("Calculator", "released", None, CONTROL["Calculator"], True),
        ("Calculator", "released", CONTROL["Calculator"], None, False),
        ("Calculator", "released", None, CONTROL["Menu"], False),
        
        # Test with invalid key
        ("InvalidKey", "pressed", CONTROL["Calculator"], None, False),
        ("InvalidKey", "released", None, CONTROL["Calculator"], False),
    ]
)
def test_key_evaluation(key_name, key_action, key_down, key_up, expected_result):
    """Test Key class evaluate() method"""
    # Setup
    key = diversion.Key([key_name, key_action], warn=False)
    
    # Set global key state
    diversion.key_down = key_down
    diversion.key_up = key_up
    
    # Test evaluation
    result = key.evaluate(None, None, None, None)
    assert result == expected_result

def test_key_str_representation():
    """Test Key class string representation"""
    key = diversion.Key(["Calculator", "pressed"], warn=False)
    expected_str = f"Key: {CONTROL['Calculator']} (pressed)"
    assert str(key) == expected_str

def test_key_data_representation():
    """Test Key class data representation"""
    key = diversion.Key(["Calculator", "pressed"], warn=False)
    expected_data = {"Key": [str(CONTROL["Calculator"]), "pressed"]}
    assert key.data() == expected_data

@pytest.mark.parametrize(
    "args, expected_warning",
    [
        ({"not": "valid"}, "rule Key arguments unknown: {'not': 'valid'}"),
        
        ("NotAKey", "rule Key key name not name of a Logitech key: NotAKey"),
        
        (["Calculator", "invalid_action"], "rule Key action unknown: invalid_action, assuming pressed"),
    ]
)
def test_key_initialization_warnings(args, expected_warning, caplog):
    with caplog.at_level(logging.WARNING):
        diversion.Key(args, warn=True)
    assert expected_warning in caplog.text

def test_key_unknown_hex_initialization(caplog):
    with caplog.at_level(logging.INFO):
        key = diversion.Key("unknown:0x1234", warn=True)
        
    assert "rule Key key name currently unknown: unknown:0x1234" in caplog.text
    assert key.key == CONTROL[0x1234]

def test_key_debug_logging(caplog):
    key = diversion.Key("Calculator", warn=False)
    
    with caplog.at_level(logging.DEBUG):
        key.evaluate(None, None, None, None)
    
    expected_debug_msg = f"evaluate condition: Key: {CONTROL['Calculator']} (pressed)"
    assert expected_debug_msg in caplog.text

@pytest.mark.parametrize(
    "args, warn, expected_logs",
    [
        (
            ["InvalidKey", "invalid_action"],
            True,
            [
                "rule Key key name not name of a Logitech key: InvalidKey",
                "rule Key action unknown: invalid_action, assuming pressed"
            ]
        ),
        (
            ["InvalidKey", "invalid_action"],
            False,
            []
        ),
    ]
)
def test_key_warning_flag(args, warn, expected_logs, caplog):
    with caplog.at_level(logging.WARNING):
        diversion.Key(args, warn=warn)
    
    for expected_log in expected_logs:
        if warn:
            assert expected_log in caplog.text
        else:
            assert expected_log not in caplog.text

def test_key_initialization_list_warnings(caplog):
    with caplog.at_level(logging.WARNING):
        fake_list = type('FakeList', (), {'__instancecheck__': lambda *_: True})()
        diversion.Key(fake_list, warn=True)
        assert "rule Key arguments unknown" in caplog.text
        
        caplog.clear()
        
        diversion.Key([123, 456], warn=True)
        assert "rule Key key name not name of a Logitech key" in caplog.text
