from __future__ import annotations

import base64
import binascii
import ctypes
import platform
import subprocess
from enum import Enum
from hashlib import md5
from typing import Union, Optional
from uuid import UUID
from pathlib import Path
import requests
from Cryptodome.Cipher import AES
import os
from random import SystemRandom, randint

class StreamFabCdm():

    class Clients(Enum):
        WINDOWS = "pc"
        ANDROID = "am"
        
    class WindowsDecryptors(Enum):
        EXE_PATH = "FabModKey.exe"
        DLL_PATH = "FabModKey.dll"

    class LinuxDecryptors(Enum):
        SO_PATH = "FabModKey.so"

    CACHED_TABLE = [
        "abema", "abematv", "amazon_pm", "amazon_jp", "amazon_us", "amazon_uk",
        "amazon_de", "appletv", "canal", "paramount", "channel", "crackle",
        "crunchyroll", "discovery", "disneyplus_us", "disneyplus_jp", "unext",
        "dtv", "fod", "gyao", "hbo_europe", "hbomax", "hulu_us", "hulu_jp", "joyn",
        "mgstage", "netflix", "paravi", "peacock", "pluto", "rakuten", "roku",
        "skyshowtime", "stan", "telasa", "tubitv", "tvnow", "viki"
    ]

    def __init__(
        self,
        client: StreamFabCdm.Clients = Clients.WINDOWS,
        windows_decryptor: StreamFabCdm.WindowsDecryptors = WindowsDecryptors.DLL_PATH,
        linux_decryptor: StreamFabCdm.LinuxDecryptors = LinuxDecryptors.SO_PATH,
        email: Optional[str] = None
    ):
        if not client:
            raise ValueError("Client must be provided")
        if isinstance(client, str):
            client = StreamFabCdm.Clients[client]
        if not isinstance(client, StreamFabCdm.Clients):
            raise TypeError(f"Expected client to be a {StreamFabCdm.Clients!r} not {client!r}")

        self.client = client
        device_id = ["".join(SystemRandom().choice("abcdef0123456789") for _ in range(2)) for _ in range(12)]

        if self.client == StreamFabCdm.Clients.WINDOWS:
            self.machine_id = ":".join(["-".join(device_id[:6]), "-".join(device_id[6:])])
            self.client_id = 95
            self.app_version = int("6.1.1.1".replace(".", ""))
        else:
            self.machine_id = "-".join(device_id[:5])
            self.client_id = 51
            self.app_version = int("2.0.0.8".replace(".", ""))

        self.email = email or self.machine_id

        self.reg_type = "trial"
        self.wid = 1
        self.ver = 1
        self.pid = randint(1000000, 9999999)

        self.__session = requests.Session()
        self.__session.headers.update({
            "Accept": "*/*",
            "User-Agent": "DVDFab"
        })
        
        self.windows_decryptor = windows_decryptor
        self.linux_decryptor = linux_decryptor
        self.current_dir = Path(__file__).resolve().parent

    def get_license_challenge(self,pssh,service_cert_b64=None):

        res = self.__session.post(
            url="https://www.deuhd.ru/v1/st/",
            data={
                "T": 10,
                "B": 6,
                "C": self.email,
                "D": "",
                "E": self.reg_type,
                "F": "",
                "G": self.client_id,
                "H": self.machine_id,
                "I": self.ver,
                "Z": self.app_version,
                "K": self.wid,
                "L": self.pid,
                "M": pssh,
                "N": service_cert_b64
            }
        ).json()

        if res["R"] != "0":
            raise ValueError(f"DVDFab API failed processing the service cert... {res}")

        processed_session_cert = res["FB"]

        res = self.__session.post(
            url="https://drm-w-j2.dvdfab.cn/mk/",
            data={
                "T": 12,
                "B": 6,
                "C": self.email,
                "D": "",
                "E": self.reg_type,
                "F": "",
                "G": self.client_id,
                "H": self.machine_id,
                "I": self.ver,
                "Z": self.app_version,
                "K": self.wid,
                "L": self.pid,
                "M": processed_session_cert
            }
        ).json()

        if res["R"] != "0":
            raise ValueError(f"DVDFab API failed signing a license challenge... {res}")

        signed_challenge_b64 = res["FB"]
        return signed_challenge_b64, processed_session_cert

    def parse_license(self, pssh, license_message, processed_session_cert):

        context = self.__session.post(
            url="https://drm-w-j2.dvdfab.cn/ml/",
            data={
                "T": 15,
                "B": 6,
                "C": self.email,
                "D": "",
                "E": self.reg_type,
                "F": "",
                "G": self.client_id,
                "H": self.machine_id,
                "I": self.wid,
                "Z": self.app_version,
                "K": self.ver,
                "L": self.pid,
                "M": license_message,
            }
        ).json()
        if context["R"] != "0":
            raise ValueError(f"DVDFab API failed decrypting a license response message... {context}")

        response = self.__session.post(
            url="https://ssl-ca.dvdfab.cn/ak/v2/li/",
            data={
                "T": 12,
                "B": 6,
                "C": self.email,
                "D": "",
                "E": self.reg_type,
                "F": "",
                "G": self.client_id,
                "H": self.machine_id,
                "I": self.wid,
                "Z": self.app_version,
                "K": self.ver,
                "L": self.pid,
                "M": pssh,
                "N": processed_session_cert,
                "O": context["FB"],
                "P": context["D"]
            }
        ).json()
        if response["R"] != "0":
            raise ValueError(f"DVDFab API failed decrypting a license response message... {response}")
            
        keys = self.get_keys(response)
        return keys

    def get_tok(self, reference: Union[int, str], cached: bool = False) -> str:
        if self.client == StreamFabCdm.Clients.WINDOWS or not cached:
            secret = "_SSKF_V1"
        else:
            secret = "_SSKF_V1_ARM"

        if cached:
            data = f"{self.email}{secret}"
        else:
            data = "{0}{1}{2}{3}".format(
                self.email,
                secret,
                self.machine_id,
                reference
            )

        return md5(data.encode("utf-8")).digest().hex()
        
    def get_cached_keys(self, kid, table):

        if isinstance(kid, bytes):
            kid = kid.hex()

        if isinstance(kid, UUID):
            kid = kid.hex
            
        url, cmd_name = self.get_cached_url_and_cmd(table)

        response = self.__session.post(
            url=url,
            data={
                "cmd": cmd_name,
                "table": f"{table}_keys",
                "kid": kid,
                "ver": 20,
                "email": self.email,
                "wid": 1,
                "pid": self.pid,
                "client_id": self.client_id,
                "reg_type": self.reg_type,
                "machine_id": self.machine_id,
                "app_version": self.app_version,
            }
        ).json()
        if not int(response.get("R", 9)) == 0:
            raise ValueError(f"DVDFab API failed get a cached key response message... {response}")
        
        keys = self.get_keys(response)
        return keys

    def get_cached_url_and_cmd(self, table: str) -> str:
        if not table in self.CACHED_TABLE:
            mode = "re"
            href = "com"
            cmd_name = "downloadcheck"
        else:
            if table == "disneyplus_us" or table == "stan":
                mode = "re"
                cmd_name = "download"
            elif table == "netflix" or "amazon" in table:
                mode = "am"
                cmd_name = "downloadcheck"
            else:
                mode = "ke"
                cmd_name = "downloadcheck"
                
            if "_" in table:
                href = table.split("_")[0] + "/" + table.split("_")[1]
            else:
                href = table

        return f"https://drm-u1.dvdfab.cn/ak/{mode}/{href}/", cmd_name
        
    def get_keys(self, res):
        if "key" in res:
            decrypted_keys = res["key"].encode("utf8")
        else:
            has_cache = "k" in res
            if has_cache:
                key_data = res["d"]
                mod_key = res["k"]
            else:
                key_data = res["D"]
                mod_key = res["T"]
            tok = self.get_tok(self.pid, cached=has_cache)

            if platform.system() == "Windows":
                if self.windows_decryptor == StreamFabCdm.WindowsDecryptors.EXE_PATH:
                    dec_key = subprocess.getoutput(f"{self.windows_decryptor.value} {mod_key} {tok}").strip()
                else:
                    lib_fab = ctypes.cdll.LoadLibrary(str(self.current_dir/self.windows_decryptor.value))
                    lib_fab.modkey2key.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    lib_fab.modkey2key.restype = ctypes.c_char_p
                    dec_key = lib_fab.modkey2key(mod_key.encode("utf-8"), tok.encode("utf-8")).decode("utf-8")
            else:
                lib_fab = ctypes.cdll.LoadLibrary(str(self.current_dir/self.linux_decryptor.value))
                lib_fab.mod_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                lib_fab.mod_key.restype = ctypes.c_char_p
                dec_key = lib_fab.mod_key(mod_key.encode("utf-8"), tok.encode("utf-8")).decode("utf-8")

            try:
                decrypted_keys = AES.\
                    new(dec_key[:16].upper().encode("utf-8"), mode=AES.MODE_ECB).\
                    decrypt(base64.b64decode(key_data))
            except Exception as e:
                raise Exception(f"Failed to decrypt DVDFab API license with {mod_key} {tok}, {e}")

        decrypted_keys = decrypted_keys.decode("utf8").rstrip().split("\n")
        keys = ""
        for key in decrypted_keys:
            if ":" in str(key):
                keys += key + "\n"
        
        return keys.strip("\n").strip("|")

__ALL__ = (StreamFabCdm,)