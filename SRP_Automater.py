#Author: Juan Ortega
#Date: 02/27/2017

from subprocess import check_output
import hashlib, os, random, string, winreg, binascii


def main():
    query_file_locations()
    with open("srp_blacklist.txt") as f_in:
        lines = list(line for line in (l.strip() for l in f_in) if line)  # only read non-blank lines
        for line in lines:
            try:
                hash = calc_hash(line)
                size = calc_filesize(line)
                block_file(hash,size)
            except:
                print ("error: " + line)
                pass
    check_output("taskkill /f /IM explorer.exe", shell=True).decode()


def query_file_locations():
    while True:
        binary = input('Enter the binary name you want to block \n'
                       'If you are finished, type "done" \n')

        try:
            if binary == 'done':
                break
            file_dir = check_output("where -R c:\ " + binary, shell=True).decode()
            f = open("srp_blacklist.txt", "a+") #+ creates the file if it doesn't exist
            #TODO: prevents the same binary being added twice to the list
            f.write(file_dir)
            f.close()
            print(file_dir.strip())
        except:
            print (binary+ " not found")
            pass


def calc_hash(line):
    md5_hash = hashlib.md5(open(line, 'rb').read()).hexdigest()
    binary_string = binascii.unhexlify(md5_hash) #required to add hex to registry key
    return binary_string


def calc_filesize(line):
    win_line = '{}'.format(line) #put around quotes to pass windows dir
    file_size = os.path.getsize(win_line)
    return file_size


def gen_valid_registry():
    part_one =''.join(random.choice(string.hexdigits + string.hexdigits) for _ in range(8))
    part_two =''.join(random.choice(string.hexdigits + string.hexdigits) for _ in range(4))
    part_three =''.join(random.choice(string.hexdigits + string.hexdigits) for _ in range(4))
    part_four =''.join(random.choice(string.hexdigits + string.hexdigits) for _ in range(4))
    part_five =''.join(random.choice(string.hexdigits+ string.hexdigits) for _ in range(12))

    joined_string = part_one+"-"+part_two+"-"+part_three+"-"+part_four+"-"+part_five
    joined_string = str.lower(joined_string)
    return joined_string


def block_file(hash,size):
    HashAlg = 32771
    key_dir = gen_valid_registry()
    srp_path = 'SOFTWARE\\Policies\\Microsoft\\Windows\\safer\\CodeIdentifiers\\0\\Hashes\\'

    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, srp_path +"{" + key_dir + "}") as srp:
        winreg.SetValueEx(srp, "HashAlg", 0, winreg.REG_DWORD, HashAlg)
        winreg.SetValueEx(srp, "ItemData", 0, winreg.REG_BINARY, hash)
        winreg.SetValueEx(srp, "ItemSize", 0, winreg.REG_QWORD, size)


if __name__ == "__main__": main()




