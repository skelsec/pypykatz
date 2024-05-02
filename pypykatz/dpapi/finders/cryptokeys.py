import pathlib
from typing import Iterator, List

from winacl.dtyp.wcee.cryptoapikey import CryptoAPIKeyFile, CryptoAPIKeyProperties

class CryptoKeysFinder:
    def __init__(self):
        self.startdir = ['ServiceProfiles','LocalService','AppData','Roaming','Microsoft','Crypto','Keys']
        self.entries:List[CryptoAPIKeyFile] = []
    
    def __iter__(self) -> Iterator[CryptoAPIKeyFile]:
        return iter(self.entries)
    
    @staticmethod
    def from_windir(win_dir: str | pathlib.Path, raise_error: bool = True):
        if isinstance(win_dir, str):
            win_dir = pathlib.Path(win_dir).absolute()
        
        if not win_dir.is_dir():
            if raise_error:
                raise ValueError(f'{win_dir} is not a directory')
            return CryptoKeysFinder()
        
        cryptokeys_dir = win_dir
        for directory in CryptoKeysFinder().startdir:
            cryptokeys_dir = cryptokeys_dir / directory
            if not cryptokeys_dir.is_dir():
                raise ValueError(f'{cryptokeys_dir} does not exist')
        
        return CryptoKeysFinder.from_dir(cryptokeys_dir)
    
    @staticmethod
    def from_dir(cryptokeys_dir: str | pathlib.Path, raise_error: bool = True):
        if isinstance(cryptokeys_dir, str):
            cryptokeys_dir = pathlib.Path(cryptokeys_dir).absolute()
        if not cryptokeys_dir.is_dir():
            if raise_error:
                raise ValueError(f'{cryptokeys_dir} is not a directory')
            return CryptoKeysFinder()
        
        finder = CryptoKeysFinder()
        
        for filepath in cryptokeys_dir.iterdir():
            if filepath.is_dir():
                continue
            
            key = CryptoAPIKeyFile.from_bytes(filepath.read_bytes())
            finder.entries.append(key)

        return finder