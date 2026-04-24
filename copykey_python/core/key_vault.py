"""
Local Encrypted Key Storage
NO NETWORK COMMUNICATION - Keys stored locally only
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


class LocalKeyVault:
    ITERATIONS = 100_000
    SALT_LEN = 16
    IV_LEN = 12
    TAG_LEN = 16
    KEY_LEN = 32

    def __init__(self, vault_path: Optional[str] = None):
        if vault_path is None:
            vault_path = str(Path.home() / '.copykey' / 'key_vault.json')
        self.vault_path = Path(vault_path)
        self.meta_path = self.vault_path.with_suffix('.meta')
        self.keys: List[Dict] = []
        self.master_key: Optional[bytes] = None
        self.unlocked: bool = False

    def create_vault(self, password: str) -> None:
        salt = get_random_bytes(self.SALT_LEN)
        self.master_key = PBKDF2(password.encode('utf-8'), salt, dkLen=self.KEY_LEN, count=self.ITERATIONS)
        self.keys = []
        self._save_vault_data()
        self._save_metadata(salt)
        self.unlocked = True
        logger.info("Key vault created")

    def unlock_vault(self, password: str) -> bool:
        metadata = self._load_metadata()
        if not metadata:
            logger.error("No vault metadata found")
            return False
        salt = bytes.fromhex(metadata['salt'])
        self.master_key = PBKDF2(password.encode('utf-8'), salt, dkLen=self.KEY_LEN, count=self.ITERATIONS)
        encrypted_data = self._load_vault_data()
        if encrypted_data:
            try:
                self.keys = self._decrypt(encrypted_data)
                self.unlocked = True
                logger.info(f"Vault unlocked: {len(self.keys)} keys loaded")
                return True
            except (ValueError, KeyError) as e:
                logger.error(f"Failed to decrypt vault: {e}")
                self.master_key = None
                return False
        else:
            self.keys = []
            self.unlocked = True
            return True

    def is_unlocked(self) -> bool:
        return self.unlocked

    def add_key(self, key: bytes, label: str = '') -> None:
        if len(key) != 6:
            raise ValueError("Key must be 6 bytes")
        entry = {
            'key': key.hex(),
            'label': label,
            'created': datetime.now().isoformat()
        }
        self.keys.append(entry)

    def remove_key(self, index: int) -> bool:
        if 0 <= index < len(self.keys):
            del self.keys[index]
            return True
        return False

    def get_all_keys(self) -> List[bytes]:
        return [bytes.fromhex(k['key']) for k in self.keys]

    def get_key_labels(self) -> List[Dict[str, str]]:
        return [{'hex': k['key'], 'label': k['label'], 'created': k['created']} for k in self.keys]

    def save_vault(self) -> None:
        if not self.master_key or not self.unlocked:
            raise RuntimeError("Vault not unlocked")
        self._save_vault_data()
        logger.info("Vault saved")

    def _encrypt(self, data: dict) -> bytes:
        iv = get_random_bytes(self.IV_LEN)
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return iv + tag + ciphertext

    def _decrypt(self, data: bytes) -> list:
        iv = data[:self.IV_LEN]
        tag = data[self.IV_LEN:self.IV_LEN + self.TAG_LEN]
        ciphertext = data[self.IV_LEN + self.TAG_LEN:]
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode('utf-8'))

    def _save_vault_data(self) -> None:
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        data = {'keys': self.keys, 'version': 1}
        encrypted = self._encrypt(data)
        self.vault_path.write_bytes(encrypted)

    def _load_vault_data(self) -> Optional[bytes]:
        if self.vault_path.exists():
            return self.vault_path.read_bytes()
        return None

    def _save_metadata(self, salt: bytes) -> None:
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        metadata = {
            'version': 1,
            'salt': salt.hex(),
            'created': datetime.now().isoformat()
        }
        with open(self.meta_path, 'w') as f:
            json.dump(metadata, f)

    def _load_metadata(self) -> Optional[dict]:
        if not self.meta_path.exists():
            return None
        with open(self.meta_path) as f:
            return json.load(f)

    def get_statistics(self) -> Dict:
        return {
            'total_keys': len(self.keys),
            'unlocked': self.unlocked,
            'vault_path': str(self.vault_path)
        }
