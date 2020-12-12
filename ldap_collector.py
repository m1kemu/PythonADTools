import ldap
import argparse
import sys
import random
import time
import json
import os
import datetime
from ldap.controls import SimplePagedResultsControl


def ldap_query(dc, description, filter, username, domain, password, domain_formatted, output_filename):
    """
    Performs the LDAP query using the supplied filter

    Args:
        dc: (string) IP address of domain controller to run the LDAP query
        description: (string) A brief description of the filter
        filter: (string) The LDAP filter
        username: (string) Username to use when running the query
        domain: (string) Domain to use when running the query
        password: (string) Password to use when running the query
        domain_formatted: (string) A well formatted version of the domain
        output_filename: (string) Name of the file to write output to
    """

    try:
        con = ldap.initialize(f"ldap://{dc}:389")
        con.set_option(ldap.OPT_REFERRALS, 0)
    except Exception as e:
        print(f"[-] Error creating LDAP connection: {str(e)}")
        sys.exit(1)

    print(f"\n[*] Searching for: {description}")
    print(f"[*] LDAP filter: {filter}\n")

    try:
        con.simple_bind_s(f"{username}@{domain}", password)
        page_control = SimplePagedResultsControl(True, size=10, cookie='')
        res = con.search_ext(domain_formatted, ldap.SCOPE_SUBTREE, filter, [], serverctrls=[page_control])
        pages = 0

        while True:
            pages += 1
            _, rdata, _, serverctrls = con.result3(res)

            for item in rdata:
                dn = item[0]
                entry = item[1]

                if dn:
                    formatted = parse_ldap_object(dn, entry)
                    print(f'\t\t{formatted}')

                    f = open(output_filename, 'a')
                    f.write("{'description': '" + description + "', 'data': " + str(formatted) + "}\n")
                    f.close()

            controls = [control for control in serverctrls if control.controlType == SimplePagedResultsControl.controlType]

            if not controls:
                print("[-] Error performing pagination")
                break
            if not controls[0].cookie:
                break

            page_control.cookie = controls[0].cookie
            res = con.search_ext(domain_formatted, ldap.SCOPE_SUBTREE, filter, [], serverctrls=[page_control])

    except Exception as e:
        print(f"[-] Error performing LDAP query: {str(e)}")


def parse_ldap_object(dn, entry):
    """
    Parses LDAP user, group, and computer entries to extract key data

    Args:
        dn: (string) The LDAP object's distinguished name
        entry: (dict) All LDAP data for the object

    Returns:
        A dict of key fields extracted from the LDAP object
    """

    if entry["objectClass"][-1].decode("utf-8") == "computer":
        try:
            hostname = entry["dNSHostName"][0].decode()
        except:
            hostname = ''

        try:
            os_version = entry["operatingSystemVersion"][0].decode()
        except:
            os_version = ''

        try:
            os = entry["operatingSystem"][0].decode()
        except:
            os = ''

        return {"dn": dn, "hostname": hostname, "os_version": os_version, "os": os}

    elif entry["objectClass"][-1].decode("utf-8") == "user":
        try:
            samaccountname = entry["sAMAccountName"][0].decode()
        except:
            samaccountname = ''

        try:
            description = entry["description"][0].decode()
        except:
            description = ''

        try:
            member_of = entry["memberOf"][0].decode()
        except:
            member_of = ''

        try:
            pwd_last_set = entry["pwdLastSet"][0].decode()
        except:
            pwd_last_set = ''

        try:
            spn = str(entry["servicePrincipalName"])
        except:
            spn = []

        return {"dn": dn, "samaccountname": samaccountname, "description": description, "member_of": member_of, "pwd_last_set": pwd_last_set, "spn": spn}

    elif entry["objectClass"][-1].decode("utf-8") == "group":
        try:
            samaccountname = entry["sAMAccountName"][0].decode()
        except:
            samaccountname = ""

        try:
            description = entry["description"][0].decode()
        except:
            description = ''

        try:
            member = str(entry["member"])
        except:
            member = []

        return {"dn": dn, "samaccountname": samaccountname, "description": description, "member": member}


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
    parser.add_argument("-u", "--username", help="Domain user username", required=True)
    parser.add_argument("-p", "--password", help="Domain user password", required=True)
    parser.add_argument("-f", "--dcfile", help="List of domain controller IPs to run queries against at random", required=False)
    parser.add_argument("-m", "--mode", help="Recon mode to run in (default 'all'): all, targeted", required=False)
    parser.add_argument("-s", "--sleep", help="Sleep time in seconds (default: 1", required=False)
    args = parser.parse_args()

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

    mode = args.mode

    if not mode in ["all", "targeted"]:
        mode = "all"

    if args.sleep:
        try:
            sleep_time = int(args.sleep)
        except Exception as e:
            print(f"[-] Error converting sleep time to int, defaulting to 1")
            sleep_time = 1
    else:
        sleep_time = 1

    print(f"[*] Using mode: {mode}")

    print(f"[*] Using these DCs for queries:")
    for dc in domain_controllers:
        print(f"\t{dc}")

    username = args.username.strip()
    password = args.password.strip()
    domain = args.domain
    domain_formatted = ""
    start_time = datetime.datetime.now().strftime("%B-%d-%Y-%I-%M")
    output_filename = f"ldap_recon-{start_time}.json"

    for chunk in domain.split('.'):
        domain_formatted += f"DC={chunk},"

    domain_formatted = domain_formatted[:-1]

    print(f"[*] Username: {username}")
    print(f"[*] Password: {password}")
    print(f"[*] Domain: {domain_formatted}")

    high_value_terms = ["*sql*", "*admin*", "a-*", "a_*", "*svc*", "s-*", "s_*", "*security*", "*devops*", "*splunk*", "*oracle*", "*cyberark*", "*thycotic*", "*vault*", "*aws*", "*crowdstrike*", "*carbonblack*", "*arcsight*", "*logrhythm*", "*database*"]

    high_value_users = "(&(samAccountType=805306368)(|"
    high_value_groups = "(&(objectCategory=group)(|"
    high_value_computers = "(&(objectClass=comuter)(|"
    for term in high_value_terms:
        high_value_users += f"(samAccountName={term})"
        high_value_groups += f"(name={term})"
        high_value_computers += "(hostname={term})"
    high_value_users += "))"
    high_value_groups += "))"
    high_value_computers += "))"

    if mode == "all":
        filters = {
                "All users": "(&(objectClass=user)(samAccountType=805306368))",
                "All computers": "(objectClass=computer)",
                "All groups": "(objectClass=group)"
                }
    else:
        filters = {
                "Domain Controllers": "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                "Kerberos pre-auth disabled users": "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                "Designated admin users": "(&(samAccountType=805306368)(admincount=1))",
                "Unconstrained computers": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                "Users with SPNs": "(&(samAccountType=805306368)(servicePrincipalName=*))",
                "Interesting usernames": high_value_users,
                "Interesting group names": high_value_groups,
                "Interesting computers": high_value_computers,
                "Users with interesting descriptions": "(&(objectClass=user)(samAccountType=805306368)(|(description=*password*)(description=*temp*)))",
                "Constrained delegation": "(msDS-AllowedToDelegateTo=*)",
                "Delegation to LDAP": "(msDS-AllowedToDelegateTo=*ldap*)",
                "Delegation to MSSQL": "(msDS-AllowedToDelegateTo=*sql*)",
                "Non-expiring passwords": "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
                "User accounts with SPNs": "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer))",
                "Change pwd at next login": "(&(objectCategory=user)(pwdLastSet=0))"
                }

    for description, filter in filters.items():
        dc = random.choice(domain_controllers)
        ldap_query(dc, description, filter, username, domain, password, domain_formatted, output_filename)
        time.sleep(sleep_time)


if __name__ == "__main__":
    main()
