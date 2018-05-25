# pypykatz
Mimikatz implementation in pure Python

## Goals
First step is to have the minidump file parsing capability done in a platform independent way, so you can enjoy watching secrets in your favourite OS.
Currently aiming for full sekurlsa::minidump functionality.

**WARNING**  
This project is still work in progress, there is no guarantee that anything will stay/look/feel the same from one second to another.

## Prerequisites
Most of my big python projects are aiming for maximum protability, meaning I only use 3rd party packages where absolutely necessary. 
As of this point only one additional package is used, and I intend to keep it this way.
  
[minidump](https://github.com/skelsec/minidump)

## Kudos
Benjamin DELPY @gentilkiwi for [Mimikatz](https://github.com/gentilkiwi/mimikatz)  
Francesco Picasso for the [mimikatz.py plugin for volatility](https://raw.githubusercontent.com/sans-dfir/sift-files/master/volatility/mimikatz.py)  
  
### Crypto
Richard Moore for the [AES module](https://github.com/ricmoo/pyaes/blob/master/pyaes/aes.py)  
Todd Whiteman for teh [DES module](http://twhiteman.netfirms.com/des.html)  
  
### Utils
David Buxton for the timestamp conversion script  

