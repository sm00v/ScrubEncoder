# ScrubEncoder
This is an alpha-numberic subtraction encoder based on VelloSec's blog found <a href="https://vellosec.net/blog/exploit-dev/carving-shellcode-using-restrictive-character-sets/">here.</a>

This program takes hexidecimal input in the format ```\x89\xE0\x66\x2D``` or ```89E0662D``` and will sub-encode the hex to alpha-numeric shellcode for restricted character exploits. As of now, every four bytes will get converted to a 26-byte chunk. I will be improving upon this to skip alpha-numeric 4-byte increments to decrease the final payload size. 


Example Output:
```
Variable name: buffer
Shellcode: \x89\xE0\x66\x2D\x9F\x0D\xFF\xD0
buffer = b""
buffer += b"\x25\x4a\x4d\x4e\x55"+ b"\x25\x35\x32\x31\x2a"
buffer += b"\x2d\x30\x78\x64\x17"+ b"\x2d\x30\x78\x64\x16"+ b"\x2d\x01\x02\x38\x01\x50"
buffer += b"\x25\x4a\x4d\x4e\x55"+ b"\x25\x35\x32\x31\x2a"
buffer += b"\x2d\x3b\x0f\x4c\x68"+ b"\x2d\x3b\x0f\x4c\x68"+ b"\x2d\x01\x01\x01\x02\x50"
Hex Payload: \x25\x4a\x4d\x4e\x55\x25\x35\x32\x31\x2a\x2d\x30\x78\x64\x17\x2d\x30\x78\x64\x16\x2d\x01\x02\x38\x01\x50\x25\x4a\x4d\x4e\x55\x25\x35\x32\x31\x2a\x2d\x3b\x0f\x4c\x68\x2d\x3b\x0f\x4c\x68\x2d\x01\x01\x01\x02\x50
Payload Size: 52
```
Note: The 'Hex Payload' is a non-formatted version of the entire payload and can be copy-pasted as is. 

TODO: Reduce payload size by skipping good 4-byte sequences

#OSCE #OffensiveSecurity #ExploitDev
