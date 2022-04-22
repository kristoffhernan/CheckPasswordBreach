from requests import get
import hashlib
from sys import argv, exit
from secrets import token_urlsafe

def request_api_data(query_char):
    # pwned api only needs the first 5 char of the hashed password
    # it then provides all pwned passwords with the same first 5 char and 
    # displays the tail end so you can match the correct tail ends
    url = f'https://api.pwnedpasswords.com/range/{query_char}' 
    res = get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {str(res.status_code)}, check the API and try again')

    return res


def get_pass_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # checking if the tail end is the same
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # turns password into hash using sha-1
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_pass[:5], sha1_pass[5:]
    # checking 
    response = request_api_data(first5_char)

    return get_pass_leaks_count(response, tail)


def get_pass_from_txt(password_file):
    # reads the passwords from text file
    with open(rf'{password_file}', 'r') as file:
        password = file.read().splitlines()
        if not password:
            raise IndexError('There are no passwords provided in the file')
        file.close()

    return password


def gen_safe_pass():
    # random url-safe text string containing 12 random bytes
    # the text is base64 encoded
    safe_pass = token_urlsafe(12)

    return safe_pass


def export_breached_password(password, count):
    with open('BreachedPasswords.txt', 'a') as file:
        file.write(f'{password}, {count}, {gen_safe_pass()}\n')
        file.close()


def main(passwords):
    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. It would be best to change your password.')
            export_breached_password(password, count)
        else:
            print(f'{password} was not found. Your password is safe!')

    return 'Scripting complete.'


if __name__ == '__main__':
    try:
        password_file = argv[1]
    except IndexError as err:
        print(f'Txt file containing lists of passwords must be included as an argument: {err}')
    else:
        passwords = get_pass_from_txt(password_file)
        exit(main(passwords))
