import base64

import json

from nucypher_core import *
from nucypher_core import MessageKit as CoreMessageKit
from nucypher_core import ReencryptionRequest as CoreReencryptionRequest
from nucypher_core import RetrievalKit as CoreRetrievalKit
from typing import Optional, Tuple, Dict, Union, List

from nucypher.policy.conditions._utils import _deserialize_condition_lingo
from nucypher.policy.conditions.evm import ContractCondition
from nucypher.policy.conditions.lingo import ConditionLingo


class BoltOnConditions:
    _CORE_CLASS = NotImplemented
    _DELIMITER = b'0xBC'  # ESCAPE

    def __init__(self,
                 *args,
                 conditions: Optional['ConditionLingo'] = None,
                 core_instance: Optional = None,
                 **kwargs):
        if not core_instance:
            core_instance = self._CORE_CLASS(*args, **kwargs)
        self._core_instance = core_instance
        self.conditions = conditions

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return getattr(self, attr)
        return getattr(self._core_instance, attr)

    def __bytes__(self):
        payload = bytes(self._core_instance)
        if self.conditions:
            payload += self._DELIMITER
            payload += bytes(self.conditions)
        return payload

    @classmethod
    def _parse(cls, data) -> Tuple[bytes, bytes]:
        if cls._DELIMITER in data:
            data, condition_bytes = data.split(cls._DELIMITER)
            return data, condition_bytes
        return data, b''  # TODO: Handle empty conditions better

    @classmethod
    def from_bytes(cls, data: bytes):
        condition = None
        if cls._DELIMITER in data:
            data, condition_bytes = cls._parse(data)
            condition = ContractCondition.from_bytes(condition_bytes)  # TODO: This might not be a contract condition but how can we know whct type it is by it's bytes only?
        core_instance = cls._CORE_CLASS.from_bytes(data)
        instance = cls(core_instance=core_instance, decryption_condition=condition)
        return instance


class RetrievalKit(BoltOnConditions):
    _CORE_CLASS = CoreRetrievalKit

    @classmethod
    def from_message_kit(cls, message_kit: MessageKit, *args, **kwargs):
        # TODO: strip away the conditions for the lower layer
        data, condition_bytes = cls._parse(bytes(message_kit))
        core_mk_instance = MessageKit._CORE_CLASS.from_bytes(data)
        core_instance = cls._CORE_CLASS.from_message_kit(message_kit=core_mk_instance, *args, **kwargs)
        instance = cls(core_instance=core_instance)
        return instance


class MessageKit(BoltOnConditions):
    _CORE_CLASS = CoreMessageKit


class ReencryptionRequest(BoltOnConditions):
    _CORE_CLASS = CoreReencryptionRequest

    def __init__(self,
                 lingos: Tuple['ConditionLingo', ...],
                 context: Optional[Dict[str, Union[str, int]]] = None,
                 *args, **kwargs):
        self.context = context
        super().__init__(conditions=lingos, *args, **kwargs)
    @property
    def lingos(self):
        return self.conditions  # hack
    def to_base64(self) -> bytes:
        data = base64.b64encode(self.to_json().encode())
        return data

    @classmethod
    def from_base64(cls, data: bytes) -> 'ReencryptionRequest':
        data = base64.b64decode(data).decode()
        instance = cls.from_json(data)
        return instance

    def to_json(self) -> str:
        # [{}, null, {...lingo..}]
        json_serialized_lingo = [l.to_dict() if l else None for l in self.lingos]
        data = json.dumps(json_serialized_lingo)
        return data

    @classmethod
    def from_json(cls, data: str) -> 'ReencryptionRequest':
        data = json.loads(data)
        lingos = [_deserialize_condition_lingo(l) for l in data]
        instance = cls(lingos=lingos)
        return instance

    @classmethod
    def from_bytes(cls, data: bytes):
        if cls._DELIMITER in data:
            data, lingos_bytes = cls._parse(data)
            json_lingos = json.loads(base64.b64decode(lingos_bytes))
            lingos = [ConditionLingo.from_list(lb) if lb else None for lb in json_lingos]
        core_instance = cls._CORE_CLASS.from_bytes(data)
        instance = cls(core_instance=core_instance, lingos=lingos)
        return instance

    def __bytes__(self):
        payload = bytes(self._core_instance)
        if self.conditions:
            payload += self._DELIMITER
            json_lingos = json.dumps([l.to_list() if l else None for l in self.lingos])
            b64_lingos = base64.b64encode(json_lingos.encode())
            payload += b64_lingos
        return payload
