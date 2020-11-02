import bitstring
import struct
from binascii import hexlify
from capstone import *

### When you're not the best or most extreme, you better get creative..

sub_one = []
sub_two = []
sub_three = []
check_overflown = { # this dict is to know which byte to modify if overflown
    '0':False,
    '1':False,
    '2':False,
    '3':False
}
def assemble(compile_me):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(compile_me, 0x00):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

def overflown(): # subtract 1 from key value - 1 if the byte is overflown (add 1 to the front of the bad byte for sub)
    for key, value in check_overflown.items():
        if value == True:
            key = int(key)
            try:
                key = key - 1
                if key == -1: # checking to see if key value is == -1 then pass
                    pass
                else:
                    sub_two[key] = sub_two[key] - 1
            except Exception:
                print('failed to subtract')
                print(key)
                print(sub_two[key])
                continue
        else:
            pass
    reset_overflown()

def reset_overflown(): # resets all overflown values to false for new 4 byte sequence
    for key, value in check_overflown.items():
        update_position = {key: False}
        check_overflown.update(update_position)

def filter_byte(inverse_list): # 3 values are produced from the single byte. each value will be appended to its list accordingly
    for value in inverse_list: # for each entry run locic (4 entries, one for each byte)
        if value == '00':  # 0x100 == 256
            dec_one = int('0x64', 16)  # 100 decimal
            dec_two = int('0x64', 16)  # 100 decimal
            dec_three = int('0x38', 16)  # 56 decimal
            sub_one.append(dec_one)
            sub_two.append(dec_two)
            sub_three.append(dec_three)
            update_position = {str(len(sub_one) - 1): True}
            check_overflown.update(update_position)
        elif value == '01':  # 0x101 == 257
            dec_one = int('0x64', 16)  # 100 decimal
            dec_two = int('0x64', 16)  # 100 decimal
            dec_three = int('0x39', 16)  # 57 decimal
            sub_one.append(dec_one)
            sub_two.append(dec_two)
            sub_three.append(dec_three)
            update_position = {str(len(sub_one) - 1): True}
            check_overflown.update(update_position)
        elif value == '02':  # 0x102 == 258
            dec_one = int('0x64', 16)  # 100 decimal
            dec_two = int('0x64', 16)  # 100 decimal
            dec_three = int('0x3a', 16)  # 58 decimal
            sub_one.append(dec_one)
            sub_two.append(dec_two)
            sub_three.append(dec_three)
            update_position = {str(len(sub_one) - 1): True}
            check_overflown.update(update_position)
        else:
            logic(value)

def nop_padding(buf):
    buf_arr = []
    for i in range(0, len(buf), 8):
        four_byte = [buf[i:i + 8]][0]
        length = len(four_byte)
        if not length % 8:
            buf_arr.append(four_byte)
        else:
            if length == 2:
                padded_bytes = four_byte + b'90' * (5 - length)
                buf_arr.append(padded_bytes)
            elif length == 4:
                padded_bytes = four_byte + b'90' * (6 - length)
                buf_arr.append(padded_bytes)
            elif length == 6:
                padded_bytes = four_byte + b'90' * (7 - length)
                buf_arr.append(padded_bytes)
            else:
                print('ERROR: CHECK IF YOU PASTED SHELLCODE PROPERLY!')
                exit()
    nop_paded_sequence = b''.join(buf_arr)
    return nop_paded_sequence

def main_control():
    variable = input('Variable name: ')
    buf = bytes(input('Shellcode: '), encoding='utf-8').replace(b'\\x', b'')
    adj_buf = nop_padding(buf)
    invert(adj_buf)
    overflown()
    sub_eax_map_r_one = map("{:02x}".format, (reversed(sub_one)))
    sub_eax_one_r = '\\x' + '\\x'.join(sub_eax_map_r_one)# big endian order shellcode
    sub_eax_map_r_two = map("{:02x}".format, (reversed(sub_two)))
    sub_eax_two_r = '\\x' + '\\x'.join(sub_eax_map_r_two)  # big endian order shellcode
    sub_eax_map_r_three = map("{:02x}".format, (reversed(sub_three)))
    sub_eax_three_r = '\\x' + '\\x'.join(sub_eax_map_r_three)  # big endian order shellcode
    format_print(sub_eax_one_r,sub_eax_two_r, sub_eax_three_r, variable)

def format_print(sub_one, sub_two, sub_three, variable):
    and_one = '\\x25\\x4a\\x4d\\x4e\\x55'  # AND EAX, 0x554E4D4A'
    and_two = '\\x25\\x35\\x32\\x31\\x2a'  # AND EAX, 0x2A313235'
    first_print=[sub_one[i:i + 16] for i in range(0, len(sub_one), 16)]
    second_print = [sub_two[i:i + 16] for i in range(0, len(sub_two), 16)]
    third_print = [sub_three[i:i + 16] for i in range(0, len(sub_three), 16)]
    print(variable + ' = b""')
    all=[]
    for sub in range(len(first_print)):
        hex_string=and_one+and_two+"\\x2d"+first_print[sub]+"\\x2d"+second_print[sub]+"\\x2d"+third_print[sub]+"\\x50"
        print(variable
              + ' += b"' + and_one + '"+ b"' + and_two + '"')
        print(variable
              + ' += b"\\x2d' + first_print[sub]
              + '"+ b"\\x2d' + second_print[sub]
              + '"+ b"\\x2d' + third_print[sub] + '\\x50"')
        all.append(hex_string)
    print('Hex Payload: ' + ''.join(all))
    print('Payload Size: ' + str(len(first_print) * 26))

def invert(buf):
    hex_bytes = buf
    for i in range(0, len(hex_bytes), 8): # select 4 bytes from list
        lilE_raw = [hex_bytes[i:i + 8]][0]
        lilE_decoded=int('0x'+lilE_raw.decode('utf-8'), 16) # decode bytes from hex and convert to integer
        lilE_int = int(hexlify(struct.pack('<L', lilE_decoded)), 16) # reverse byte order using struct
        inverse_decimal = int(0-lilE_int) # subtract reversed bytes from 0
        inverse_hex=bitstring.BitArray('int:64=' + str(inverse_decimal)).hex[8:] # a hack to get the proper lower 32 bits of shellcode with bad bytes
        inverse_list = [inverse_hex[i:i + 2 ]for i in range(0, len(inverse_hex), 2)] # iterate every two characters into a list to format for hex
        filter_byte(inverse_list) # pass to the overflow checker

def logic(value): # this function helps create the sub eax statements. 3 values are produced from the single byte. each value will be appended to its list accordingly
    integer = (int(value, 16))
    check_integer = (integer/2).is_integer()
    if check_integer:
        dec_one = (int(integer / 2) - 1)
        dec_two = (int(integer / 2) - 1)
        dec_three = (2)
        sub_one.append(dec_one)
        sub_two.append(dec_two)
        sub_three.append(dec_three)
    else:
        dec_one = (int(integer / 2))
        dec_two = (int(integer / 2))
        dec_three =(1)
        sub_one.append(dec_one)
        sub_two.append(dec_two)
        sub_three.append(dec_three)

main_control()

# TODO: Reduce payload size by skipping good 4 byte sequences