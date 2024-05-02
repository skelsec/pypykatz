import pathlib
from aiowinreg.filestruct.header import NTRegistryHeadr

class RegFinder:
    def __init__(self):
        self.startdir = ['System32','config']
        self.entries = {
            'SAM': None,
            'SECURITY': None,
            'SYSTEM': None,
            'SOFTWARE': None,
        }
    
    @staticmethod
    def from_windir(windir: str | pathlib.Path, raise_error: bool = True):
        """Searches for the registry hives in the Windows directory. Do not use on live systems."""
        if isinstance(windir, str):
            windir = pathlib.Path(windir).absolute()
        if not windir.is_dir():
            raise ValueError(f'{windir} is not a directory')
        finder = RegFinder()
        regdir = windir
        for directory in finder.startdir:
            regdir = regdir / directory
            if not regdir.is_dir():
                if raise_error:
                    raise ValueError(f'{regdir} does not exist')
                return finder.entries
        
        for filepath in regdir.iterdir():
            if filepath.is_dir():
                continue
            
            if filepath.name.upper().endswith('SAM'):
                finder.entries['SAM'] = filepath
            
            if filepath.name.upper().endswith('SECURITY'):
                finder.entries['SECURITY'] = filepath

            if filepath.name.upper().endswith('SYSTEM'):
                finder.entries['SYSTEM'] = filepath
            
            if filepath.name.upper().endswith('SOFTWARE'):
                finder.entries['SOFTWARE'] = filepath

        return finder.entries
    
    @staticmethod
    def from_dir(reg_dir: str | pathlib.Path, raise_error: bool = True):
        """Searches for the registry hives in the directory."""
        finder = RegFinder()
        if isinstance(reg_dir, str):
            reg_dir = pathlib.Path(reg_dir).absolute()
        if not reg_dir.is_dir():
            if raise_error:
                raise ValueError(f'{reg_dir} is not a directory')
            return finder.entries
        
        for filepath in reg_dir.iterdir():
            if filepath.is_dir():
                continue
            
            try:
                with open(filepath, 'rb') as f:
                    header = NTRegistryHeadr.read(f)
                    if header.file_name.upper().endswith('SAM'):
                        finder.entries['SAM'] = filepath
                    if header.file_name.upper().endswith('SECURITY'):
                        finder.entries['SECURITY'] = filepath
                    if header.file_name.upper().endswith('SYSTEM'):
                        finder.entries['SYSTEM'] = filepath
                    if header.file_name.upper().endswith('SOFTWARE'):
                        finder.entries['SOFTWARE'] = filepath

            except Exception as e:
                print(f'Error reading {filepath}: {e}')
                continue

        return finder.entries