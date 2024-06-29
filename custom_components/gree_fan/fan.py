#!/usr/bin/python
# Do basic imports
import base64
import logging
import math
import socket
from typing import Any

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from Crypto.Cipher import AES
from homeassistant.components.fan import (
    FanEntity,
    FanEntityFeature,
    PLATFORM_SCHEMA
)
from homeassistant.const import (
    CONF_HOST,
    CONF_MAC,
    CONF_NAME,
    CONF_PORT,
    CONF_TIMEOUT,
)
from homeassistant.util.percentage import int_states_in_range, percentage_to_ranged_value, ranged_value_to_percentage

try:
    import simplejson
except ImportError:
    import json as simplejson
from datetime import timedelta

REQUIREMENTS = ['pycryptodome']

_LOGGER = logging.getLogger(__name__)

SUPPORT_FLAGS = FanEntityFeature.SET_SPEED | FanEntityFeature.OSCILLATE

DEFAULT_NAME = 'Gree Fan'

CONF_ENCRYPTION_KEY = 'encryption_key'
CONF_UID = 'uid'
CONF_HORIZONTAL_SWING = 'horizontal_swing'
CONF_ENCRYPTION_VERSION = 'encryption_version'
CONF_DISABLE_AVAILABLE_CHECK = 'disable_available_check'
CONF_MAX_ONLINE_ATTEMPTS = 'max_online_attempts'

DEFAULT_PORT = 7000
DEFAULT_TIMEOUT = 10
DEFAULT_TARGET_TEMP_STEP = 1

# update() interval
SCAN_INTERVAL = timedelta(seconds=60)

FAN_MODES = ['Normal', 'Sleep', 'Other1', 'Other2']
SWING_MODES = ['Default', '60 degree', '100 degree', '360 degree']

GCM_IV = b'\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13'
GCM_ADD = b'qualcomm-test'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PORT, default=DEFAULT_PORT): cv.positive_int,
    vol.Required(CONF_MAC): cv.string,
    vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
    vol.Optional(CONF_ENCRYPTION_KEY): cv.string,
    vol.Optional(CONF_UID): cv.positive_int,
    vol.Optional(CONF_ENCRYPTION_VERSION, default=1): cv.positive_int,
    vol.Optional(CONF_HORIZONTAL_SWING, default=False): cv.boolean,
    vol.Optional(CONF_DISABLE_AVAILABLE_CHECK, default=False): cv.boolean,
    vol.Optional(CONF_MAX_ONLINE_ATTEMPTS, default=3): cv.positive_int
})


async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    _LOGGER.info('Setting up Gree climate platform')
    name = config.get(CONF_NAME)
    ip_addr = config.get(CONF_HOST)
    port = config.get(CONF_PORT)
    mac_addr = config.get(CONF_MAC).encode().replace(b':', b'')
    timeout = config.get(CONF_TIMEOUT)

    fan_modes = FAN_MODES
    swing_modes = SWING_MODES
    encryption_key = config.get(CONF_ENCRYPTION_KEY)
    uid = config.get(CONF_UID)
    horizontal_swing = config.get(CONF_HORIZONTAL_SWING)
    encryption_version = config.get(CONF_ENCRYPTION_VERSION)
    disable_available_check = config.get(CONF_DISABLE_AVAILABLE_CHECK)
    max_online_attempts = config.get(CONF_MAX_ONLINE_ATTEMPTS)

    _LOGGER.info('Adding Gree climate device to hass')

    async_add_devices([
        GreeFan(hass, name, ip_addr, port, mac_addr, timeout, fan_modes, swing_modes, horizontal_swing,
                encryption_version, disable_available_check, max_online_attempts, encryption_key, uid)
    ])


class GreeFan(FanEntity):

    def __init__(self, hass, name, ip_addr, port, mac_addr, timeout, fan_modes, swing_modes, horizontal_swing,
                 encryption_version, disable_available_check, max_online_attempts, encryption_key=None, uid=None,
                 max_step=12):
        _LOGGER.info('Initialize the GREE climate device')
        self.hass = hass
        self._name = name
        self._ip_addr = ip_addr
        self._port = port
        self._mac_addr = mac_addr.decode('utf-8').lower()
        self._timeout = timeout
        self._device_online = None
        self._online_attempts = 0
        self._max_online_attempts = max_online_attempts
        self._disable_available_check = disable_available_check

        self._fan_mode = None
        self._swing_mode = None
        self._fan_speed = None

        self._fan_modes = fan_modes
        self._swing_modes = swing_modes

        self.encryption_version = encryption_version
        self.CIPHER = None
        self._step_range: tuple[int, int] | None = (1, max_step) if max_step else None

        if encryption_key:
            _LOGGER.info('Using configured encryption key: {}'.format(encryption_key))
            self._encryption_key = encryption_key.encode("utf8")
            if encryption_version == 1:
                # Cipher to use to encrypt/decrypt
                self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
            elif encryption_version != 2:
                _LOGGER.error('Encryption version %s is not implemented.' % encryption_version)
        else:
            self._encryption_key = None

        self._horizontal_swing = horizontal_swing

        if uid:
            self._uid = uid
        else:
            self._uid = 0

        self._acOptions = {'Pow': None, 'Mod': None, 'WdSpd': None, 'SwingLfRig': None, 'SwUpDn': None}

        self._firstTimeRun = True

        self._unique_id = 'fan.gree_' + mac_addr.decode('utf-8').lower()

    # Pad helper method to help us get the right string for encrypting
    def Pad(self, s):
        aesBlockSize = 16
        return s + (aesBlockSize - len(s) % aesBlockSize) * chr(aesBlockSize - len(s) % aesBlockSize)

    def FetchResult(self, cipher, ip_addr, port, timeout, json):
        _LOGGER.info('Fetching(%s, %s, %s, %s)' % (ip_addr, port, timeout, json))
        clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSock.settimeout(timeout)
        clientSock.sendto(bytes(json, "utf-8"), (ip_addr, port))
        data, addr = clientSock.recvfrom(64000)
        receivedJson = simplejson.loads(data)
        clientSock.close()
        pack = receivedJson['pack']
        base64decodedPack = base64.b64decode(pack)
        decryptedPack = cipher.decrypt(base64decodedPack)
        if self.encryption_version == 2:
            tag = receivedJson['tag']
            cipher.verify(base64.b64decode(tag))
        decodedPack = decryptedPack.decode("utf-8")
        replacedPack = decodedPack.replace('\x0f', '').replace(decodedPack[decodedPack.rindex('}') + 1:], '')
        loadedJsonPack = simplejson.loads(replacedPack)
        return loadedJsonPack

    def GetDeviceKey(self):
        _LOGGER.info('Retrieving HVAC encryption key')
        GENERIC_GREE_DEVICE_KEY = "a3K8Bx%2r8Y7#xDh"
        cipher = AES.new(GENERIC_GREE_DEVICE_KEY.encode("utf8"), AES.MODE_ECB)
        pack = base64.b64encode(
            cipher.encrypt(self.Pad('{"mac":"' + str(self._mac_addr) + '","t":"bind","uid":0}').encode("utf8"))).decode(
            'utf-8')
        jsonPayloadToSend = '{"cid": "app","i": 1,"pack": "' + pack + '","t":"pack","tcid":"' + str(
            self._mac_addr) + '","uid": 0}'
        try:
            self._encryption_key = \
                self.FetchResult(cipher, self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['key'].encode(
                    "utf8")
        except:
            _LOGGER.info('Error getting device encryption key!')
            self._device_online = False
            self._online_attempts = 0
            return False
        else:
            _LOGGER.info('Fetched device encrytion key: %s' % str(self._encryption_key))
            self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
            self._device_online = True
            self._online_attempts = 0
            return True

    def GetGCMCipher(self, key):
        cipher = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
        cipher.update(GCM_ADD)
        return cipher

    def EncryptGCM(self, key, plaintext):
        encrypted_data, tag = self.GetGCMCipher(key).encrypt_and_digest(plaintext.encode("utf8"))
        pack = base64.b64encode(encrypted_data).decode('utf-8')
        tag = base64.b64encode(tag).decode('utf-8')
        return (pack, tag)

    def GetDeviceKeyGCM(self):
        _LOGGER.info('Retrieving HVAC encryption key')
        GENERIC_GREE_DEVICE_KEY = b'{yxAHAY_Lm6pbC/<'
        plaintext = '{"cid":"' + str(self._mac_addr) + '", "mac":"' + str(self._mac_addr) + '","t":"bind","uid":0}'
        pack, tag = self.EncryptGCM(GENERIC_GREE_DEVICE_KEY, plaintext)
        jsonPayloadToSend = '{"cid": "app","i": 1,"pack": "' + pack + '","t":"pack","tcid":"' + str(
            self._mac_addr) + '","uid": 0, "tag" : "' + tag + '"}'
        try:
            self._encryption_key = \
                self.FetchResult(self.GetGCMCipher(GENERIC_GREE_DEVICE_KEY), self._ip_addr, self._port, self._timeout,
                                 jsonPayloadToSend)['key'].encode("utf8")
        except:
            _LOGGER.info('Error getting device encryption key!')
            self._device_online = False
            self._online_attempts = 0
            return False
        else:
            _LOGGER.info('Fetched device encrytion key: %s' % str(self._encryption_key))
            self._device_online = True
            self._online_attempts = 0
            return True

    def GreeGetValues(self, propertyNames):
        plaintext = '{"cols":' + simplejson.dumps(propertyNames) + ',"mac":"' + str(self._mac_addr) + '","t":"status"}'
        if self.encryption_version == 1:
            cipher = self.CIPHER
            jsonPayloadToSend = '{"cid":"app","i":0,"pack":"' + base64.b64encode(
                cipher.encrypt(self.Pad(plaintext).encode("utf8"))).decode('utf-8') + '","t":"pack","tcid":"' + str(
                self._mac_addr) + '","uid":{}'.format(self._uid) + '}'
        elif self.encryption_version == 2:
            pack, tag = self.EncryptGCM(self._encryption_key, plaintext)
            jsonPayloadToSend = '{"cid":"app","i":0,"pack":"' + pack + '","t":"pack","tcid":"' + str(
                self._mac_addr) + '","uid":{}'.format(self._uid) + ',"tag" : "' + tag + '"}'
            cipher = self.GetGCMCipher(self._encryption_key)
        return self.FetchResult(cipher, self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['dat']

    def SetAcOptions(self, acOptions, newOptionsToOverride, optionValuesToOverride=None):
        if not (optionValuesToOverride is None):
            _LOGGER.info('Setting acOptions with retrieved HVAC values')
            for key in newOptionsToOverride:
                _LOGGER.info('Setting %s: %s' % (key, optionValuesToOverride[newOptionsToOverride.index(key)]))
                acOptions[key] = optionValuesToOverride[newOptionsToOverride.index(key)]
            _LOGGER.info('Done setting acOptions')
        else:
            _LOGGER.info('Overwriting acOptions with new settings')
            for key, value in newOptionsToOverride.items():
                _LOGGER.info('Overwriting %s: %s' % (key, value))
                acOptions[key] = value
            _LOGGER.info('Done overwriting acOptions')
        return acOptions

    def SendStateToAc(self, timeout):
        _LOGGER.info('Start sending state to HVAC')
        statePackJson = '{' + '"opt":["Pow","Mod","WdSpd","SwingLfRig","SwUpDn"],"p":[{Pow},{Mod},{WdSpd},{SwingLfRig},{SwUpDn}],"t":"cmd"'.format(
            **self._acOptions) + '}'
        if self.encryption_version == 1:
            cipher = self.CIPHER
            sentJsonPayload = '{"cid":"app","i":0,"pack":"' + base64.b64encode(
                cipher.encrypt(self.Pad(statePackJson).encode("utf8"))).decode('utf-8') + '","t":"pack","tcid":"' + str(
                self._mac_addr) + '","uid":{}'.format(self._uid) + '}'
        elif self.encryption_version == 2:
            pack, tag = self.EncryptGCM(self._encryption_key, statePackJson)
            sentJsonPayload = '{"cid":"app","i":0,"pack":"' + pack + '","t":"pack","tcid":"' + str(
                self._mac_addr) + '","uid":{}'.format(self._uid) + ',"tag":"' + tag + '"}'
            cipher = self.GetGCMCipher(self._encryption_key)
        receivedJsonPayload = self.FetchResult(cipher, self._ip_addr, self._port, timeout, sentJsonPayload)
        _LOGGER.info('Done sending state to HVAC: ' + str(receivedJsonPayload))

    def UpdateHAOptions(self):
        if self._acOptions['WdSpd']:
            self._fan_speed = self._acOptions['WdSpd']

    def UpdateHACurrentSwingMode(self):
        # Sync current HVAC Swing mode state to HA
        self._swing_mode = self._swing_modes[self._acOptions['SwUpDn']]
        _LOGGER.info('HA swing mode set according to HVAC state to: ' + str(self._swing_mode))

    def UpdateHAFanMode(self):
        self._fan_mode = self._fan_modes[int(self._acOptions['Mod'])]
        _LOGGER.info('HA fan mode set according to HVAC state to: ' + str(self._fan_mode))

    def UpdateHAStateToCurrentACState(self):
        self.UpdateHAOptions()
        self.UpdateHACurrentSwingMode()
        self.UpdateHAFanMode()

    def SyncState(self, acOptions={}):
        # Fetch current settings from HVAC
        _LOGGER.info('Starting SyncState')

        optionsToFetch = ["Pow", "Mod", "WdSpd", "SwingLfRig", "SwUpDn"]

        try:
            currentValues = self.GreeGetValues(optionsToFetch)
        except:
            _LOGGER.info('Could not connect with device. ')
            if not self._disable_available_check:
                self._online_attempts += 1
                if (self._online_attempts == self._max_online_attempts):
                    _LOGGER.info(
                        'Could not connect with device %s times. Set it as offline.' % self._max_online_attempts)
                    self._device_online = False
                    self._online_attempts = 0
        else:
            if not self._disable_available_check:
                if not self._device_online:
                    self._device_online = True
                    self._online_attempts = 0
            # Set latest status from device
            self._acOptions = self.SetAcOptions(self._acOptions, optionsToFetch, currentValues)

            # Overwrite status with our choices
            if not (acOptions == {}):
                self._acOptions = self.SetAcOptions(self._acOptions, acOptions)

            # Initialize the receivedJsonPayload variable (for return)
            receivedJsonPayload = ''

            # If not the first (boot) run, update state towards the HVAC
            if not (self._firstTimeRun):
                if not (acOptions == {}):
                    # loop used to send changed settings from HA to HVAC
                    self.SendStateToAc(self._timeout)
            else:
                # loop used once for Gree Climate initialisation only
                self._firstTimeRun = False

            # Update HA state to current HVAC state
            self.UpdateHAStateToCurrentACState()

            _LOGGER.info('Finished SyncState')
            return receivedJsonPayload

    @property
    def should_poll(self):
        _LOGGER.info('should_poll()')
        # Return the polling state.
        return True

    @property
    def available(self):
        if self._disable_available_check:
            return True
        else:
            if self._device_online:
                _LOGGER.info('available(): Device is online')
                return True
            else:
                _LOGGER.info('available(): Device is offline')
                return False

    def update(self):
        _LOGGER.info('update()')
        if not self._encryption_key:
            if self.encryption_version == 1:
                if self.GetDeviceKey():
                    self.SyncState()
            elif self.encryption_version == 2:
                if self.GetDeviceKeyGCM():
                    self.SyncState()
            else:
                _LOGGER.error('Encryption version %s is not implemented.' % self.encryption_version)
        else:
            self.SyncState()

    @property
    def name(self):
        _LOGGER.info('name(): ' + str(self._name))
        # Return the name of the climate device.
        return self._name

    @property
    def swing_mode(self):
        _LOGGER.info('swing_mode(): ' + str(self._swing_mode))
        # get the current swing mode
        return self._swing_mode

    @property
    def swing_modes(self):
        _LOGGER.info('swing_modes(): ' + str(self._swing_modes))
        # get the list of available swing modes
        return self._swing_modes

    @property
    def fan_mode(self):
        _LOGGER.info('fan_mode(): ' + str(self._fan_mode))
        # Return the fan mode.
        return self._fan_mode

    @property
    def fan_modes(self):
        _LOGGER.info('fan_list(): ' + str(self._fan_modes))
        # Return the list of available fan modes.
        return self._fan_modes

    @property
    def supported_features(self):
        _LOGGER.info('supported_features(): ' + str(SUPPORT_FLAGS))
        # Return the list of supported features.
        return SUPPORT_FLAGS

    @property
    def unique_id(self):
        # Return unique_id
        return self._unique_id

    def set_swing_mode(self, swing_mode):
        _LOGGER.info('Set swing mode(): ' + str(swing_mode))
        # set the swing mode
        if not (self._acOptions['Pow'] == 0):
            # do nothing if HVAC is switched off
            _LOGGER.info('SyncState with SwingLfRig=' + str(swing_mode))
            self.SyncState({'SwingLfRig': self._swing_modes.index(swing_mode)})
            self.schedule_update_ha_state()

    def set_fan_mode(self, fan):
        _LOGGER.info('set_fan_mode(): ' + str(fan))
        # Set the fan mode.
        if not (self._acOptions['Pow'] == 0):
            _LOGGER.info('Setting normal fan mode to ' + str(self._fan_modes.index(fan)))
            self.SyncState({'Mod': str(self._fan_modes.index(fan))})
            self.schedule_update_ha_state()

    def set_fan_speed(self, fan):
        _LOGGER.info('set_fan_speed(): ' + str(fan))
        # Set the fan mode.
        if not (self._acOptions['Pow'] == 0):
            _LOGGER.info('Setting fan speed to ' + str(fan))
            self.SyncState({'WdSpd': fan})
            self.schedule_update_ha_state()

    def turn_on(self,
                percentage: int | None = None,
                preset_mode: str | None = None,
                **kwargs: Any, ):
        _LOGGER.info('turn_on(): ')
        # Turn on.
        c = {'Pow': 1}
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_off(self):
        _LOGGER.info('turn_off(): ')
        # Turn off.
        c = {'Pow': 0}
        self.SyncState(c)
        self.schedule_update_ha_state()

    async def async_added_to_hass(self):
        _LOGGER.info('Gree climate device added to hass()')
        self.update()

    @property
    def speed_count(self) -> int:
        """Return the number of speeds the fan supports."""
        if self._step_range is None:
            return super().speed_count
        return int_states_in_range(self._step_range)

    @property
    def percentage(self) -> int | None:
        """Return the current speed as a percentage."""
        if self._fan_speed is None:
            return None

        if self._step_range:
            return ranged_value_to_percentage(
                self._step_range, self._fan_speed
            )
        return self._fan_speed

    async def async_set_percentage(self, percentage: int) -> None:
        """Set the speed of the fan, as a percentage."""
        if self._step_range:
            step = math.ceil(percentage_to_ranged_value(self._step_range, percentage))
            self.set_fan_speed(step)
        else:
            self.set_fan_speed(percentage)

    def oscillate(self, oscillating: bool) -> None:
        """Oscillate the fan."""
        if oscillating is True:
            self.set_swing_mode('60 degree')
        else:
            self.set_swing_mode('Default')

    @property
    def is_on(self) -> bool | None:
        """Return true if the entity is on."""
        if self._acOptions['Pow'] is not None:
            return self._acOptions['Pow'] == 1
        return (
                self.percentage is not None and self.percentage > 0
        ) or self.preset_mode is not None

    @property
    def oscillating(self) -> bool | None:
        """Return whether or not the fan is currently oscillating."""
        return not self.swing_mode == 'Default'
