import pathlib
from typing import Iterator, List

class NGCProtector:
    def __init__(self):
        self.sid = None
        self.path = None
        self.provider = None
        self.guid = None


class NGCProtectorFinder:
    def __init__(self):
        self.startdir = ['ServiceProfiles','LocalService','AppData','Local','Microsoft','Ngc']
        self.entries:List[NGCProtector] = []
    
    def __iter__(self) -> Iterator[NGCProtector]:
        return iter(self.entries)
    
    @staticmethod
    def from_windir(win_dir: str | pathlib.Path, raise_error: bool = True):
        if isinstance(win_dir, str):
            win_dir = pathlib.Path(win_dir).absolute()
        
        if not win_dir.is_dir():
            raise ValueError(f'{win_dir} is not a directory')
        
        ngc_dir = win_dir
        for directory in NGCProtectorFinder().startdir:
            ngc_dir = ngc_dir / directory
            if not ngc_dir.is_dir():
                raise ValueError(f'{ngc_dir} does not exist')
        
        return NGCProtectorFinder.from_dir(ngc_dir, raise_error=raise_error)
    
    @staticmethod
    def from_dir(ngc_dir: str | pathlib.Path, raise_error: bool = True):
        if isinstance(ngc_dir, str):
            ngc_dir = pathlib.Path(ngc_dir).absolute()
        if not ngc_dir.is_dir():
            if raise_error:
                raise ValueError(f'{ngc_dir} is not a directory')
            return NGCProtectorFinder()
        finder = NGCProtectorFinder()
        
        for directory in ngc_dir.iterdir():
            if not directory.is_dir():
                continue
            if directory.name.startswith('{') and directory.name.endswith('}'):
                sid_file_path = ngc_dir / directory / '1.dat'
                fpd = ngc_dir / directory / 'Protectors' / '1'
                if not sid_file_path.exists():
                    print(f'NGC missing SID file at: {sid_file_path}')
                    continue
                
                if not fpd.exists():
                    print(f'NGC missing Protector directory at: {directory}')
                    continue

                sid = sid_file_path.read_text('utf-16-le').strip('\x00')
                pfp = fpd / '1.dat'
                if not pfp.exists():
                    print(f'NGC missing Protector file at: {pfp}')
                    continue

                gfp = fpd / '2.dat'
                if not gfp.exists():
                    print(f'NGC missing GUID file at: {gfp}')
                    continue


                protector = NGCProtector()
                protector.sid = sid
                protector.provider = pfp.read_text('utf-16-le').strip('\x00')
                protector.guid = gfp.read_text('utf-16-le').strip('\x00')
                protector.path = fpd
                finder.entries.append(protector)
        return finder
