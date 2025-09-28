#!/usr/bin/python3
import random
import string 

def generate_unique_signature():
    """
    Function will create a random file name to store the command output before it is read in and returned back to the user

    Return: random file name to avoid signatures, or at least limit signature exposure
    """
    guid_or_not = random.randint(1,10)
    if guid_or_not % 2 == 0:

        rand_length = random.randint(8, 32)
        if rand_length % 2 == 0:
            guid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=rand_length))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return '{' + ''.join(guid2) + '}'
        else:
            guid = list(''.join(random.choices(string.ascii_uppercase + string.digits, k=rand_length)))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return '{' + ''.join(guid2) + '}'
    else:

        rand_length = random.randint(8, 32)
        if rand_length % 2 == 0:
            guid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=rand_length))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return ''.join(guid2)
        else:
            guid = list(''.join(random.choices(string.ascii_uppercase + string.digits, k=rand_length)))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return ''.join(guid2)
        

def generate_temp_permutation(option):
    """
    Function will create a permutation on the Temp directory altering its case, results in upper and lower case mix

    Return: a random case on Temp
    """
    letters_dir = ['t', 'e', 'm', 'p']
    letters_cmd = ['c', 'm', 'd', '.', 'e', 'x', 'e']
    letters_power = ['p', 'o', 'w', 'e', 'r', 's', 'h', 'e', 'l', 'l', '.', 'e', 'x', 'e']
    final_arr = []
    if option == "dir":
        for i in letters_dir:
            rand_num = random.randint(1, 2)
            if rand_num == 1:
                final_arr.append(i.upper())
            else:
                final_arr.append(i.lower())
    elif option == "cmd":
        for i in letters_cmd:
            rand_num = random.randint(1, 2)
            if rand_num == 1:
                final_arr.append(i.upper())
            else:
                final_arr.append(i.lower())
    elif option == "power":
        for i in letters_power:
            rand_num = random.randint(1, 2)
            if rand_num == 1:
                final_arr.append(i.upper())
            else:
                final_arr.append(i.lower())

    else:
        pass
    return ''.join(final_arr)