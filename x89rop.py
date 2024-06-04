#!/usr/bin/python3
import sys
import argparse

#parse arguments###############################################################################
fname = None
bad_bytes = b''
bad_commands = []
allowed_reg = []
dereference = False
add_esp_size = 0

parser = argparse.ArgumentParser(prog='x89rop', description='Filter saved rop gadget output from rp++')
parser.add_argument('f', help='path to the file from rp++ to filter')
parser.add_argument('--b', help='hex byte values to filter out')
parser.add_argument('--c', help='comma separated list of commands to filter out')
parser.add_argument('--r', help='filter by register')
parser.add_argument('--d', action='store_true', help='only include dereference commands')
parser.add_argument('--dup', action='store_true', help='remove duplicate values')
parser.add_argument('--e', help='find "add esp" gadgets that equal or exceed the argument value')
parser.add_argument('--i', action='store_true', help='find interesting gadgets')
args = parser.parse_args()

if (args.f is not None): fname = args.f 
else: 
    print("error: the following arguments are required: --f=[rp++ output file name]")
    exit(1)
if (args.b is not None): bad_bytes = bytes.fromhex(args.b)     
if (args.c is not None): bad_commands = args.c.split(',')
if (args.r is not None): allowed_reg = args.r.split(',')
if (args.d is not None): dereference = True
if (args.e is not None): add_esp_size = int(args.e, 16)
################################################################################################

def xformatbytes(raw_bytes):
    """
    Format bytes.    
    """
    s = ''
    cnt = 0
    for b in raw_bytes:
        h = format(b, '02x') #format byte as two digit hex
        s += "\\x" + h   #prepend \x 
        cnt+= 1
    return s

def remove_bad_addresses(gadgets):
    '''
    Check gadget address values for bytes in the bad_chars list.
    
    Attributes:
    gadgets: list of gadget tuples (address, operations)
    '''
    global bad_bytes
    fgadgets = [] #filtered gadgets
    
    print(f"[+] removing gadgets with illegal addresses using bad_bytes {xformatbytes(bad_bytes)}")
    for g in gadgets:
        good = True
        hex_value = bytes.fromhex(g[0][2:])
        for byte in hex_value:
            if byte in bad_bytes:
                good = False
                break
        if (good):
            fgadgets.append(g)
    print(f"[+] {len(gadgets)-len(fgadgets)} gadgets removed")
    return fgadgets

def remove_duplicates(gadgets):
    '''
    Filter out duplicate commands.  Preserves the first seen gadget.
    
    Attributes:
    gadgets: list of gadget tuples (address, operations)
    '''
    fgadgets = [] #grouped gadgets
    seen = []

    print(f"[+] removing duplicates from {len(gadgets)} gadgets")
    for g in gadgets:
        if g[1] not in seen:
            fgadgets.append(g)
            seen.append(g[1])
    print(f"[+] {len(gadgets)-len(fgadgets)} gadgets removed")
    return fgadgets

def remove_bad_commands(gadgets):
    '''
    Filter out commands that are in the bad_commands list.
    
    Attributes:
    gadgets: list of gadget tuples (address, operations)
    '''
    global bad_commands
    fgadgets = [] #grouped gadgets
    
    print(f"[+] removing gadgets with illegal commands using bad_commands {bad_commands}")
    for g in gadgets:
        command_found = any(substring in g[1] for substring in bad_commands)
        if not command_found:
            fgadgets.append(g)  
    print(f"[+] {len(gadgets)-len(fgadgets)} gadgets removed")          
    return fgadgets

def filter_by_register(gadgets):
    '''
    Filter out any commands that operate on registers that are not in the list.
    '''
    global allowed_reg
    fgadgets = [] #filtered gadgets

    print(f"[+] filtering gadgets by register list {allowed_reg}")
    for g in gadgets:
        reg_found = any(substring in g[1] for substring in allowed_reg)
        if reg_found:
            fgadgets.append(g)  
    print(f"[+] {len(gadgets)-len(fgadgets)} gadgets removed")          
    return fgadgets

def filter_by_dereference(gadgets):
    '''
    Filter out any commands that are not dereference operations, ie. mov [***],
    '''
    dref = ['mov [e', 'mov  [e']
    fgadgets = [] #filtered gadgets
    
    print(f"[+] filtering dereference gadgets")
    for g in gadgets:
        dref_found = any(substring in g[1] for substring in dref)
        if dref_found:
            fgadgets.append(g)  
    print(f"[+] {len(gadgets)-len(fgadgets)} gadgets removed")          
    return fgadgets

def find_interesting_gadgets(gadgets):
    '''
    Filter interesting gadgets from a predefined list.
    '''
    cmds = ['push','pop','not','neg','xchg','mov','xor','add','sub','inc','dec','ret','and','(1 found)', ' ']
    ig = ['not eax', 'not ecx', 'neg ecx', 'neg eax', 'pop ecx', 'pop eax', 'add eax, ecx', 'sub eax, ecx', 'push esp', 'inc eax', 'inc ecx', 'xor eax, eax',
          'xor ecx, ecx', 'mov esi, eax', 'mov  [', 'add e', 'xchg eax, esp']
    shown = []

    print("\n--------------------------------------------------------------------------------------------------------")
    print("--------------------------------  Interesting Gadgets (no dupes) ---------------------------------------\n")
    for g in gadgets:
        cmd_array = g[1].split(';')
        for cmd in cmd_array:
            good_cmds = True
            cmd = cmd.strip()
            c = cmd.split(' ')[0].strip()  #
            if (c not in cmds and cmd != '(1 found)'): 
                good_cmds = False
                break
        if (good_cmds):    
            if ( any(substring in g[1] for substring in cmds) ):
                ig_found = any(substring in g[1] for substring in ig)
                if ig_found:
                    if (g[1] not in shown):
                        print (f"{g[0]}: {g[1]}")
                        shown.append(g[1])  
    
def find_large_add_esp(gadgets):
    print("\n----------------------------------------------------------------------------------------------------------")
    print("---------------------------------------  Large add esp Gadgets -------------------------------------------\n")
    for g in gadgets:
        cmd_array = g[1].split(';')
        for cmd in cmd_array:
            cmd = cmd.strip()
            cmd_parts = cmd.split(' ')
            if (len(cmd_parts) >= 3):
                c1 = cmd_parts[0].strip()  
                if (c1 == "add"):
                    c2 = cmd_parts[1].strip()
                    if (c2 == "esp,"):  
                        c3 = cmd_parts[2].strip()
                        try:
                            if (len(c3) > 0 and c3[0] == "0"): #this is a hex number
                                size = int(c3, 16)
                                if (size >= add_esp_size):
                                    print (f"{g[0]}: {g[1]}") 
                        except:
                            print(f"error {g}")

def main():
    global args
    gadgets = [] #list of gadget tuples (address, instruction)
    #open file and read in gadgets
    with open(fname, "r") as file:
        for line in file:
            if (line.startswith('0x')):
                parts = line.split(":", maxsplit=1)
                gadgets.append((parts[0].strip(), parts[1].strip()))
                   
    if (args.b is not None): gadgets = remove_bad_addresses(gadgets)
    if (args.dup): gadgets = remove_duplicates(gadgets)
    if (args.c is not None): gadgets = remove_bad_commands(gadgets)
    if (args.r is not None): gadgets = filter_by_register(gadgets)
    if (args.d): gadgets = filter_by_dereference(gadgets)
        
    if (args.e is None and not args.i):
        for g in gadgets:
            print(g[0] + ": " + g[1])
    
    if (args.e is not None): find_large_add_esp(gadgets)
    if (args.i): find_interesting_gadgets(gadgets)

if __name__ == "__main__":
    main()
