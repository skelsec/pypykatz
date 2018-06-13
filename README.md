# pypykatz
Mimikatz implementation in pure Python. -offline minidump parsing currently-  
Runs on all OS's which support python>=3.6

## Usage
Install prerequirements
```
pip3 install minidump minikerberos asn1crypto
```
Clone this repo
```
git clone https://github.com/skelsec/pypykatz.git
cd pypykatz
```
Have fun
```
python3 pypykatz.py <dumpfile>
```
## Useful commands
**Foreword: there is an awesome help menu as well.**  

### Store output in file:  
Parameter: ```-o <output_file>```  
Example: 
```
pypykatz.py <dumpfile> -o <output_file>
```
### Store JSON output in file
Parameter: ```--json```  
Example: 
```
pypykatz.py <dumpfile> --json -o <output file>
```
### Directory parsing AKA "I have some dmp files and want to get a meaningful output from ALL of them"
Parameter: ```-d```  
Example:  
```
pypykatz.py <folder_with_dumpfiles> -d --json -o <output file>
```
### Recursive parsing AKA "Okay, I actually run a botnet that sends me those files"
Parameter: ```-r```  
Example:  
```
pypykatz.py <folder_with_folder_of_dumpfiles> -d -r --json -o <output file>
```
### Debug info AKA "Feel like a haxx0r"
Parameter: ```-vv```  
Example:  
```
pypykatz.py <dumpfile> -vv
```

### Kerberos 
The kerberos tickets will be dumped BOTH in ```.kirbi``` and ```.ccache``` format.  
**WARNING!** An output directory is expected, as the ```.kirbi``` format supports only ONE ticket/file so get prepared to be swimming in those files when dealing with multiple/large dump files.  
  
Parameter: ```-k <output_dir>```  
Example:  
```
pypykatz.py <dumpfile> -vv
```

# HELP WANTED
If you want to help me getting this project into a stable release you can send mindiumps of the lsass.exe process to the following link: https://pypykatz.ocloud.de/index.php/s/NTErmGJxA42irfj  
IMPORTANT: please *DO NOT* send dumps of your own machine's lsass process!!! I will be able to see your secrets including hashes/passwords! Send dump files from machines like virtual test systems on which you don't mind that someone will see the credentials. (if you have a test domain system where kerberos is set up that would be the best)  
Also I'd apprechiate if you wouldn't spam me...  
### Why do I need these dumps files?
In order to create mimikatz in Python one would have to create structure difinitions of a gazillion different structures (check the original code) without the help of the build-in parser that you'd naturally get from using a native compiler. Now, the problem is that even a single byte misalignemt will render the parsing of these structures run to an error. Problem is mostly revolving around 32 - 64 aligments, so 32 bit Windows version lsass dumps are apprechiated as well!  
### Summary
I need data I can verify the code on and administer necessary changes on the parsers until everything works fine.  
Submitting issues on this github page wouldn't help at all without the actual file and github wouldn't like 40-300Mb file attachments.


## Goals
First step is to have the minidump file parsing capability done in a platform independent way, so you can enjoy watching secrets in your favourite OS.
Currently aiming for full sekurlsa::minidump functionality.

**WARNING**  
This project is still work in progress, there is no guarantee that anything will stay/look/feel the same from one second to another.

## Prerequisites
Most of my big python projects are aiming for maximum protability, meaning I only use 3rd party packages where absolutely necessary. 
As of this point three additional packages are used, and I intend to keep it this way.

Python>=3.6  
[minidump](https://github.com/skelsec/minidump)  
[minikerberos](https://github.com/skelsec/minikerberos)  
[asn1crypto](https://github.com/wbond/asn1crypto)  

## Kudos
Benjamin DELPY @gentilkiwi for [Mimikatz](https://github.com/gentilkiwi/mimikatz)  
Francesco Picasso for the [mimikatz.py plugin for volatility](https://raw.githubusercontent.com/sans-dfir/sift-files/master/volatility/mimikatz.py)  
  
### Crypto
Richard Moore for the [AES module](https://github.com/ricmoo/pyaes/blob/master/pyaes/aes.py)  
Todd Whiteman for teh [DES module](http://twhiteman.netfirms.com/des.html)  
  
### Utils
David Buxton for the timestamp conversion script  

