from dataclasses import dataclass
from functools import partial
from unittest import mock

import pytest

from logitech_receiver import base
from logitech_receiver import common
from logitech_receiver import exceptions
from logitech_receiver import receiver

from . import fake_hidpp


@pytest.fixture
def nano_recv():
    device_info = DeviceInfo("12", product_id=0xC534)
    mock_low_level = LowLevelInterfaceFake(responses_lacking)
    yield receiver.create_receiver(mock_low_level, device_info, lambda x: x)


class LowLevelInterfaceFake:
    def __init__(self, responses=None):
        self.responses = responses

    def open_path(self, path):
        return fake_hidpp.open_path(path)

    def product_information(self, usb_id: int) -> dict:
        return base.product_information(usb_id)

    def find_paired_node(self, receiver_path: str, index: int, timeout: int):
        return None

    def request(self, response, *args, **kwargs):
        func = partial(fake_hidpp.request, self.responses)
        return func(response, *args, **kwargs)

    def ping(self, response, *args, **kwargs):
        func = partial(fake_hidpp.ping, self.responses)
        return func(response, *args, **kwargs)

    def close(self, *args, **kwargs):
        pass


@pytest.mark.parametrize(
    "index, expected_kind",
    [
        (0, None),
        (1, 2),  # mouse
        (2, 2),  # mouse
        (3, 1),  # keyboard
        (4, 3),  # numpad
        (5, None),
    ],
)
def test_get_kind_from_index(index, expected_kind):
    mock_receiver = mock.Mock()

    if expected_kind:
        assert receiver._get_kind_from_index(mock_receiver, index) == expected_kind
    else:
        with pytest.raises(exceptions.NoSuchDevice):
            receiver._get_kind_from_index(mock_receiver, index)


@dataclass
class DeviceInfo:
    path: str
    vendor_id: int = 1133
    product_id: int = 0xC52B


responses_unifying = [
    fake_hidpp.Response("000000", 0x8003, "FF"),
    fake_hidpp.Response("000300", 0x8102),
    fake_hidpp.Response("0316CC9CB40506220000000000000000", 0x83B5, "03"),
    fake_hidpp.Response("20200840820402020700000000000000", 0x83B5, "20"),
    fake_hidpp.Response("21211420110400010D1A000000000000", 0x83B5, "21"),
    fake_hidpp.Response("22220840660402010700000000020000", 0x83B5, "22"),
    fake_hidpp.Response("30198E3EB80600000001000000000000", 0x83B5, "30"),
    fake_hidpp.Response("31811119511A40000002000000000000", 0x83B5, "31"),
    fake_hidpp.Response("32112C46EA1E40000003000000000000", 0x83B5, "32"),
    fake_hidpp.Response("400B4D58204D61737465722033000000", 0x83B5, "40"),
    fake_hidpp.Response("41044B35323020202020202020202020", 0x83B5, "41"),
    fake_hidpp.Response("42054372616674000000000000000000", 0x83B5, "42"),
    fake_hidpp.Response("012411", 0x81F1, "01"),
    fake_hidpp.Response("020036", 0x81F1, "02"),
    fake_hidpp.Response("03AAAC", 0x81F1, "03"),
    fake_hidpp.Response("040209", 0x81F1, "04"),
]
responses_c534 = [
    fake_hidpp.Response("000000", 0x8003, "FF", handle=0x12),
    fake_hidpp.Response("000209", 0x8102, handle=0x12),
    fake_hidpp.Response("0316CC9CB40502220000000000000000", 0x83B5, "03", handle=0x12),
    fake_hidpp.Response("00000445AB", 0x83B5, "04", handle=0x12),
]
responses_unusual = [
    fake_hidpp.Response("000000", 0x8003, "FF", handle=0x13),
    fake_hidpp.Response("000300", 0x8102, handle=0x13),
    fake_hidpp.Response("00000445AB", 0x83B5, "04", handle=0x13),
    fake_hidpp.Response("0326CC9CB40508220000000000000000", 0x83B5, "03", handle=0x13),
]
responses_lacking = [
    fake_hidpp.Response("000000", 0x8003, "FF", handle=0x14),
    fake_hidpp.Response("000300", 0x8102, handle=0x14),
    fake_hidpp.Response("000001", 0x8100, handle=0x14),  # For enable_notifications - success
    fake_hidpp.Response("000003", 0x8100, handle=0x14),  # For get_notifications - flags=3
]

mouse_info = {
    "kind": common.NamedInt(2, "mouse"),
    "polling": "8ms",
    "power_switch": common.NamedInt(1, "base"),
    "serial": "198E3EB8",
    "wpid": "4082",
}
c534_info = {"kind": common.NamedInt(0, "unknown"), "polling": "", "power_switch": "(unknown)", "serial": None, "wpid": "45AB"}


@pytest.mark.parametrize(
    "device_info, responses, handle, serial, max_devices, ",
    [
        (DeviceInfo(path=None), [], False, None, None),
        (DeviceInfo(path=11), [], None, None, None),
        (DeviceInfo(path="11"), responses_unifying, 0x11, "16CC9CB4", 6),
        (DeviceInfo(path="12", product_id=0xC534), responses_c534, 0x12, "16CC9CB4", 2),
        (DeviceInfo(path="12", product_id=0xC539), responses_c534, 0x12, "16CC9CB4", 2),
        (DeviceInfo(path="13"), responses_unusual, 0x13, "26CC9CB4", 1),
        (DeviceInfo(path="14"), responses_lacking, 0x14, None, 1),
    ],
)
def test_receiver_factory_create_receiver(device_info, responses, handle, serial, max_devices):
    mock_low_level = LowLevelInterfaceFake(responses)

    if handle is False:
        with pytest.raises(Exception):  # noqa: B017
            receiver.create_receiver(mock_low_level, device_info, lambda x: x)
    elif handle is None:
        r = receiver.create_receiver(mock_low_level, device_info, lambda x: x)
        assert r is None
    else:
        r = receiver.create_receiver(mock_low_level, device_info, lambda x: x)
        assert r.handle == handle
        assert r.serial == serial
        assert r.max_devices == max_devices


@pytest.mark.parametrize(
    "device_info, responses, firmware, codename, remaining_pairings, pairing_info, count",
    [
        (DeviceInfo("11"), responses_unifying, 3, "K520", -1, mouse_info, 3),
        (DeviceInfo("12", product_id=0xC534), responses_c534, None, None, 4, c534_info, 2),
        (DeviceInfo("13", product_id=0xCCCC), responses_unusual, None, None, -1, c534_info, 3),
    ],
)
def test_receiver_factory_props(device_info, responses, firmware, codename, remaining_pairings, pairing_info, count):
    mock_low_level = LowLevelInterfaceFake(responses)

    r = receiver.create_receiver(mock_low_level, device_info, lambda x: x)

    assert len(r.firmware) == firmware if firmware is not None else firmware is None
    assert r.device_codename(2) == codename
    assert r.remaining_pairings() == remaining_pairings
    assert r.device_pairing_information(1) == pairing_info
    assert r.count() == count


@pytest.mark.parametrize(
    "device_info, responses, status_str, strng",
    [
        (DeviceInfo("11"), responses_unifying, "No paired devices.", "<UnifyingReceiver(11,17)>"),
        (DeviceInfo("12", product_id=0xC534), responses_c534, "No paired devices.", "<NanoReceiver(12,18)>"),
        (DeviceInfo("13", product_id=0xCCCC), responses_unusual, "No paired devices.", "<Receiver(13,19)>"),
    ],
)
def test_receiver_factory_string(device_info, responses, status_str, strng):
    mock_low_level = LowLevelInterfaceFake(responses)

    r = receiver.create_receiver(mock_low_level, device_info, lambda x: x)

    assert r.status_string() == status_str
    assert str(r) == strng


@pytest.mark.parametrize(
    "device_info, responses",
    [
        (DeviceInfo("14"), responses_lacking),
        (DeviceInfo("14", product_id="C534"), responses_lacking),
    ],
)
def test_receiver_factory_no_device(device_info, responses):
    mock_low_level = LowLevelInterfaceFake(responses)

    r = receiver.create_receiver(mock_low_level, device_info, lambda x: x)

    with pytest.raises(exceptions.NoSuchDevice):
        r.device_pairing_information(1)


@pytest.mark.parametrize(
    "address, data, expected_online, expected_encrypted",
    [
        (0x03, b"\x01\x02\x03", True, False),
        (0x10, b"\x61\x02\x03", False, True),
    ],
)
def test_notification_information_nano_receiver(nano_recv, address, data, expected_online, expected_encrypted):
    _number = 0
    notification = base.HIDPPNotification(
        report_id=0x01,
        devnumber=0x52C,
        sub_id=0,
        address=address,
        data=data,
    )
    online, encrypted, wpid, kind = nano_recv.notification_information(_number, notification)

    assert online == expected_online
    assert encrypted == expected_encrypted
    assert wpid == "0302"
    assert kind == "keyboard"


def test_extract_serial_number():
    response = b'\x03\x16\xcc\x9c\xb4\x05\x06"\x00\x00\x00\x00\x00\x00\x00\x00'

    serial_number = receiver.extract_serial(response[1:5])

    assert serial_number == "16CC9CB4"


def test_extract_max_devices():
    response = b'\x03\x16\xcc\x9c\xb4\x05\x06"\x00\x00\x00\x00\x00\x00\x00\x00'

    max_devices = receiver.extract_max_devices(response)

    assert max_devices == 6


@pytest.mark.parametrize(
    "response, expected_remaining_pairings",
    [
        (b"\x00\x03\x00", -1),
        (b"\x00\x02\t", 4),
    ],
)
def test_extract_remaining_pairings(response, expected_remaining_pairings):
    remaining_pairings = receiver.extract_remaining_pairings(response)

    assert remaining_pairings == expected_remaining_pairings


def test_extract_codename():
    response = b"A\x04K520"

    codename = receiver.extract_codename(response)

    assert codename == "K520"


def test_extract_power_switch_location():
    response = b"0\x19\x8e>\xb8\x06\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    ps_location = receiver.extract_power_switch_location(response)

    assert ps_location == "base"


def test_extract_connection_count():
    response = b"\x00\x03\x00"

    connection_count = receiver.extract_connection_count(response)

    assert connection_count == 3


def test_extract_wpid():
    response = b"@\x82"

    res = receiver.extract_wpid(response)

    assert res == "4082"


def test_extract_polling_rate():
    response = b"\x08@\x82\x04\x02\x02\x07\x00\x00\x00\x00\x00\x00\x00"

    polling_rate = receiver.extract_polling_rate(response)

    assert polling_rate == 130


@pytest.mark.parametrize(
    "data, expected_device_kind",
    [
        (0x00, "unknown"),
        (0x03, "numpad"),
    ],
)
def test_extract_device_kind(data, expected_device_kind):
    device_kind = receiver.extract_device_kind(data)

    assert str(device_kind) == expected_device_kind


def test_enable_connection_notifications_success(nano_recv):
    """Test enabling connection notifications successfully"""
    # Add responses in correct order for the full sequence
    nano_recv.low_level.responses = [
        # Response for set_notification_flags - success response
        fake_hidpp.Response("000003", 0x8100, handle=0x12),  # Return 3 for success
        # Response for get_notification_flags - return value 3
        fake_hidpp.Response("000003", 0x8100, handle=0x12),  # Return 3 for flags
    ]
    
    result = nano_recv.enable_connection_notifications(True)
    
    assert result == 3  # Flag bits returned from get_notification_flags

def test_enable_connection_notifications_failure(nano_recv):
    """Test enabling connection notifications when set_flags fails"""
    nano_recv.low_level.responses = [
        # Empty response for set_notification_flags to simulate failure
        fake_hidpp.Response(None, 0x8100, handle=0x12),  # Use None to indicate failure
        # Still need valid 3-byte response for get_notification_flags
        fake_hidpp.Response("000000", 0x8100, handle=0x12),  # 3 bytes of data
    ]
    
    result = nano_recv.enable_connection_notifications(True)
    
    assert result is None


def test_notify_devices_failure(nano_recv):
    """Test notify_devices when write_register fails"""
    nano_recv.low_level.responses = [
        fake_hidpp.Response("", 0x8002, handle=0x12)  # Use correct sub-id 0x8002
    ]
    
    nano_recv.notify_devices()
    
    # No assertion needed - just verifying it handles failure gracefully

def test_register_new_device_success(nano_recv):
    """Test registering a new device successfully"""
    # Reset responses and add complete sequence needed
    nano_recv.low_level.responses = [
        # Response for device_pairing_information
        fake_hidpp.Response("000209", 0x8102, handle=0x12),
        # Response for extended pairing info
        fake_hidpp.Response("0316CC9CB40502220000000000000000", 0x83B5, handle=0x12),
        # Response for device info
        fake_hidpp.Response("00000445AB", 0x83B5, "04", handle=0x12),
    ]
    
    device = nano_recv.register_new_device(1)
    
    assert device is not None
    assert device.number == 1
    assert device.wpid == "45AB"
    assert device.online is True

def test_register_new_device_with_notification(nano_recv):
    """Test registering device with notification info"""
    notification = base.HIDPPNotification(
        report_id=0x01,
        devnumber=1,
        sub_id=0x41,  # DJ_PAIRING
        address=0x03,
        data=b"\x01\x02\x03",
    )
    
    # Reset responses and add complete sequence
    nano_recv.low_level.responses = [
        fake_hidpp.Response("000209", 0x8102, handle=0x12),
        fake_hidpp.Response("0316CC9CB40502220000000000000000", 0x83B5, handle=0x12),
        fake_hidpp.Response("00000445AB", 0x83B5, "04", handle=0x12),
    ]
    
    device = nano_recv.register_new_device(1, notification)
    
    assert device is not None
    assert device.number == 1
    assert device.online is True

def test_register_new_device_already_registered(nano_recv):
    """Test registering a device number that's already registered"""
    # First register a device successfully
    nano_recv.low_level.responses = [
        fake_hidpp.Response("000209", 0x8102, handle=0x12),
        fake_hidpp.Response("0316CC9CB40502220000000000000000", 0x83B5, handle=0x12),
        fake_hidpp.Response("00000445AB", 0x83B5, "04", handle=0x12),
    ]
    device = nano_recv.register_new_device(1)
    assert device is not None  # Verify first registration worked
    
    # Try to register same number again
    with pytest.raises(IndexError):
        nano_recv.register_new_device(1)

def test_register_new_device_fails(nano_recv):
    """Test registering a device when pairing info can't be read"""
    # Reset responses and add failing response
    nano_recv.low_level.responses = [
        fake_hidpp.Response("", 0x8102, handle=0x12)
    ]
    
    device = nano_recv.register_new_device(1)
    
    assert device is None
    assert 1 in nano_recv._devices  # Device number is registered as None
    assert nano_recv._devices[1] is None
