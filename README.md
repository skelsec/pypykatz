# pypykatz
Mimikatz implementation in pure Python

# Goals
First step is to have the minidump file parsing capability done in a platform independent way, so you can enjoy watching secrets in your favourite OS.
Currently aiming for full sekurlsa::minidump functionality.

**WARNING**  
This project is still work in progress, there is no guarantee that anything will stay/look/feel the same from one second to another.

# Prerequisites
Most of my big python projects are aiming for maximum protability, meaning I only use 3rd party packages where absolutely necessary. 
As of this point only one additional package is used, and I intend to keep it this way.
  
[minidump](https://github.com/skelsec/minidump)
