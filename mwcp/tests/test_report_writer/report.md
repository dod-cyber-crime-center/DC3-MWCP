# File: input_file.bin
| Field        | Value                                                            |
|:-------------|:-----------------------------------------------------------------|
| Parser       | FooParser                                                        |
| File Path    | C:/input_file.bin                                                |
| Description  | SuperMalware Implant                                             |
| Architecture |                                                                  |
| MD5          | 1e50210a0202497fb79bc38b6ade6c34                                 |
| SHA1         | baf34551fecb48acc3da868eb85e1b6dac9de356                         |
| SHA256       | 1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee |
| Compile Time |                                                                  |
| Report Tags  | tagging, test                                                    |

## Alphabet
| Alphabet                                                          |   Base |
|:------------------------------------------------------------------|-------:|
| 0123456789ABCDEF                                                  |     16 |
| ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=                                 |     32 |
| ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= |     64 |

## Command
| Value                  |
|:-----------------------|
| cmd.exe /c notepad.exe |

## Credential
| Username   | Password   |
|:-----------|:-----------|
| admin      | 123456     |
| mruser     |            |
|            | secrets    |
| admin      | pass       |

## Crypto Address
| Address                            | Symbol   |
|:-----------------------------------|:---------|
| 14qViLJfdGaP4EeHnDyJbEGQysnCpwk3gd | BTC      |

## Decoded String
| Value      | Key    | Algorithm   |
|:-----------|:-------|:------------|
| GetProcess |        |             |
| badstring  | 0xffff | xor         |

## Email Address
| Value         |
|:--------------|
| email@bad.com |

## Encryption Key
| Key                    | Algorithm   | Mode   | Iv         |
|:-----------------------|:------------|:-------|:-----------|
| 0x68656c6c6f ("hello") | rc4         |        |            |
| 0xffffffff             | aes         | ecb    | 0x00000000 |
| 0xffff                 | xor         |        |            |

## Event
| Value          |
|:---------------|
| MicrosoftExist |

## Injection Process
| Value   |
|:--------|
| svchost |

## Interval
|   Value |
|--------:|
|       3 |

## Mission ID
| Value   |
|:--------|
| target4 |

## Mutex
| Value            |
|:-----------------|
| ithinkimalonenow |

## Path
| Path                            | Is Dir   | Posix   |
|:--------------------------------|:---------|:--------|
| C:\windows\temp\1\log\keydb.txt | False    | False   |
| %APPDATA%\foo                   | True     | False   |
| C:\foo\bar.txt                  | False    | False   |
| malware.exe                     | False    |         |
| %System%\svohost.exe            | False    | False   |

## Pipe
| Value             |
|:------------------|
| \.\pipe\namedpipe |

## RSA Private Key
| Value                                                                                                                                                                                                                                                                   |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Modulus (n):<br>    187 (0xbb)<br>Public Exponent (e):<br>    7 (0x7)<br>Private Exponent (d):<br>    23 (0x17)<br>p:<br>    17 (0x11)<br>q:<br>    11 (0xb)<br>d mod (p-1):<br>    7 (0x7)<br>d mod (q-1):<br>    3 (0x3)<br>(inverse of q) mod p:<br>    14 (0xe)<br> |

## RSA Public Key
| Value                                                                     |
|:--------------------------------------------------------------------------|
| Modulus (n):<br>    187 (0xbb)<br>Public Exponent (e):<br>    7 (0x7)<br> |

## Registry
| Tags   | Key                                                              | Value   | Data          | Data Type   |
|:-------|:-----------------------------------------------------------------|:--------|:--------------|:------------|
|        | HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run | Updater | c:\update.exe | REG_SZ      |
|        | HKEY_LOCAL_MACHINE\Foo\Bar                                       |         |               |             |
| tag2   |                                                                  | Baz     |               |             |

## Service
| Name                  | Display Name            | Description                                                            | Image                |
|:----------------------|:------------------------|:-----------------------------------------------------------------------|:---------------------|
| WindowsUserManagement | Windows User Management | Provides a common management to access information about windows user. | %System%\svohost.exe |

## Socket
| Address     |   Port | Network Protocol   | Listen   |
|:------------|-------:|:-------------------|:---------|
| bad.com     |     21 | tcp                |          |
|             |   1635 | udp                |          |
|             |   4568 | tcp                | True     |
| 10.11.10.13 |    443 |                    |          |
| 192.168.1.1 |     80 | tcp                |          |
| badhost.com |     21 |                    |          |

## URL
| Tags   | Url                                      | Address     |   Port | Path              | Application Protocol   | Network Protocol   | Username   | Password   |
|:-------|:-----------------------------------------|:------------|-------:|:------------------|:-----------------------|:-------------------|:-----------|:-----------|
|        | https://10.11.10.13:443/images/baner.jpg | 10.11.10.13 |    443 | /images/baner.jpg | https                  |                    |            |            |
| proxy  |                                          | 192.168.1.1 |     80 |                   |                        | tcp                | admin      | pass       |
|        | ftp://badhost.com:21                     | badhost.com |     21 |                   | ftp                    |                    | admin      | pass       |

## UUID
| Value                                |
|:-------------------------------------|
| 654e5cff-817c-4e3d-8b01-47a6f45ae09a |

## User Agent
| Value                                              |
|:---------------------------------------------------|
| Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2) |

## Version
| Value   |
|:--------|
| 3.1     |
| 403.10  |

## Miscellaneous
| Tags      | Key          | Value                   |
|:----------|:-------------|:------------------------|
| something | misc_info    | some miscellaneous info |
|           | random_data  | b'\xde\xad\xbe\xef'     |
|           | keylogger    | True                    |
| tag1      | misc_integer | 432                     |

## Residual Files
| Filename   | Description                        | Derivation   | MD5                              | Arch   | Compile Time   |
|:-----------|:-----------------------------------|:-------------|:---------------------------------|:-------|:---------------|
| config.xml | Extracted backdoor Foo config file | embedded     | 8c41f2802904e53469390845cfeb2b28 |        |                |

# File Tree
```
<input_file.bin (1e50210a0202497fb79bc38b6ade6c34) : SuperMalware Implant>
```

