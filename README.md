# pypykatz
Mimikatz implementation in pure Python. -optimized for offline persing, but has options for live credential dumping as well-  
Runs on all OS's which support python>=3.6

## Installing
Install it via pip or by cloning it from github.  
The installer will create a pypykatz executable in the python's Script directory. You can run it from there, should be in your PATH.  

### Via PIP
```
pip3 install pypykatz
```
### Via Github
Install prerequirements
```
pip3 install minidump minikerberos asn1crypto
```
Clone this repo
```
git clone https://github.com/skelsec/pypykatz.git
cd pypykatz
```
Install it
```
python3 setup.py install
```
## Quickwin
Dumping LIVE system LSA secrets  
```
pypykatz live lsa
```  

Parsing minidump file of the LSASS process  
```
pypykatz minidump <minidump file>
```  


## Using pypykatz -detailed-
**Foreword: there is an awesome help menu as well.**  
The command structure is the following  
```
pypykatz <ouput options> <command> <subcommand (opt)>
```

### Output options
Omitting the ```-o``` filed will result in output being printed to ```stdout```   
  
#### Debug info
Increasing the number of ```v``` increases the size of memory to be shown on the screen.  
**Warning! Too much data might result in cross-boundary read attempts!**
Parameter: ```-v```  
Example:  
```
pypykatz.py -vv mindidump <minidumpfile>
```

#### Write output to file:  
Parameter: ```-o <output_file>```  
Example: 
```
pypykatz.py -o <output_file> minidump <dumpfile> 
```
  
#### Write output in JSON
Together with the ```-o``` option it will write the output to a file, otherwise will print the output to ```stdout```   

Parameter: ```--json```  
Example: 
```
pypykatz.py --json -o <output file> minidump <dumpfile> 
```  
### Kerberos 
Stores the kerberos tickets in BOTH ```.kirbi``` and ```.ccache``` formats to the directory given.  
**WARNING!** An output directory is expected, as the ```.kirbi``` format supports only ONE ticket/file so get prepared to be swimming in those files when dealing with multiple/large dump files.  
  
Parameter: ```-k <output_dir>```  
Example:  
```
pypykatz.py -k <output_dir> minidump <dumpfile>
```

### Minidump command options  
#### Directory parsing
This parameter tells pypykatz to look for all ```.dmp``` files in a given directory  

Parameter: ```-d```  
Example:  
```
pypykatz.py minidump <folder_with_dumpfiles> -d 
```  

#### Recursive parsing
Supplying this parameter will force pypykatz to recursively look for ```.dmp``` files  
Only works together with directory parsing.   

Parameter: ```-r```  
Example:  
```
pypykatz.py minidump <folder_with_folder_of_dumpfiles> -d -r
```  
### Rekall command options 
#### Timestamp override
Reason for this parameter to exist: In order to choose the correct structure for parsing we need the tiomestamp info of the msv dll file. Rekall sadly doesnt always have this info for some reason, therefore the parsing may be failing.  
If the parsing is failing this could solve the issue.  
  
Parameter: ```-t```  
Values: ```0``` or ```1```  
Example:  
```
pypykatz.py rekall <momeory_dump_file> -t 0
```  

## Rekall usage
There are two ways to use rekall-based memory parsing.  
### Via the ```pypykatz rekall``` command
You will need to specify the memory file to parse.  
  
### Via rekall command line
IMPORTANT NOTICES: 
1. If you are just now deciding to install ```rekall``` please note: it MUST be run in a virtualenv, and you will need to install pypykatz in the same virtualenv!  
2. rekall command line is not suitable to show all information acquired from the memory, you should use the ```out_file``` and ```kerberos_dir``` command switches!     
   
You can find a rekall plugin file named ```pypykatz_rekall.py``` in the ```plugins``` folder of pypykatz.  
You will need to copy it in rekall's ```plugins/windows``` folder, and rename it to ```pypykatz.py```.  
After this modify the ```__init__.py``` file located the same folder and add the following line at the end: ```from rekall.plugins.windows import pypykatz```  
If everything is okay you can use the ```pypykatz``` command from the ```rekall``` command line directly.

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

