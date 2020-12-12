import re
import argparse
import time
import sys
from base64 import b64decode
from binascii import unhexlify
from Crypto.Cipher import AES
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA

def list_shares(con):
    """
    Extracts a list of shares from the SMB connection and returns them

    Args:
        con: (SMBConnection) The SMB connection object

    Returns:
        A list of share objects
    """

    shares = [share["shi1_netname"][:-1] for share in con.listShares()]

    return shares


def check_file(share, id, con, file_dict, extensions, keywords, size_limit):
    """
    Performs various operations on a file in a share, including size check, extension check, and content check

    Args:
        share: (share object) The share containing the file to check
        id: (int) The share ID
        con: (SMBConnection) The SMB connection objects
        file_dict: (dict) A dictionary of information about the file
        extensions: (list) A list of extensions being searches for
        keywords: (list) A list of keywords being searched for
        size_limit: (int) If a file is greater than this, it will not be analyzed

    Returns:
        None
    """

    size_limit = size_limit * 1000000
    file_name = file_dict['longname']
    file_size = file_dict['size']
    path = file_dict['path']
    file_extension = file_name.split('.')[-1].lower()
    counter = 0

    extensions_tmp = []

    for extension in extensions:
        extensions_tmp.append(extension.lower())

    extensions = extensions_tmp

    if size_limit >= file_size:
        if file_extension in extensions:
            try:
                file_handle = con.openFile(id, f"{path}/{file_name}")
                
                offset = 0
                file_contents = ''

                while True:
                    if counter > 0:
                        break

                    try:
                        file_contents = con.readFile(id, file_handle, offset, 4096)
                        offset += len(file_contents)
                        file_contents = str(file_contents).lower()
                       
                        if not file_contents:
                            break
                    
                    except SessionError as e:
                        if 'STATUS_END_OF_FILE' in str(e):
                            break

                    try:
                        con.closeFile(id, file_handle)
                    except:
                        break

                    for keyword in keywords:
                        if file_contents.find(keyword.lower()) != 0:
                            counter += 1
                            print(f"[+] Keyword match for \"{keyword}\" within {file_name}")
                            break

            except Exception as e:
                print(f"[-] Error reading file contents: {str(e)}")
    else:
        pass


def check_share_access(shares, con):
    """
    Checks if a list of shares are accessible

    Args:
        shares: (list) A list of share objects
        con: (SMBConnection) The SMB connection objects

    Returns:
        A list of shares that were accessible
    """

    accessible = []

    for share in shares:
        try:
            tree_id = con.connectTree(share)
            print(f"[+] Share is accessible: {share}")
            accessible.append({'name': share, 'id': tree_id})
        except Exception as e:
            print(f"[-] Share is not accessible: {share}, {str(e)}")
            continue

    return accessible


def sysvol_crawl(share, id, con, extensions, keywords, size_limit, depth_limit, path, current_depth):
    """
    Performs crawling of the SYSVOL share

    Args:
        share: (share object) The share object to crawl
        id: (int) The share ID
        con: (SMBConnection) SMB connection object
        extensions: (list) List of extensions to check for
        keywords: (list) List of keywords to check for
        size_limit: (int) The maximum file size to scan
        depth_limit: (int) The maximum number of directories to crawl
        path: (string) The current directory path being crawled, used for recursive crawling
        current_depth: (int) The current dept being crawled, used for recursive crawling

    Returns:
        None
    """

    current_depth += 1

    print(f"[*] Crawling share: {share}")
    print(f"[*] Using extended search logic: searching for cpassing, DefaultPassword, and an extended set of keywords and extensions")
    print(f"[*] Current path: {path}")
    print(f"[*] Current depth: {str(current_depth)} of limit {str(depth_limit)}")

    keywords = keywords + ['cpassword', 'defaultpassword', 'password', 'pass', 'logon', 'username', 'credential', 'token', 'login']
    extensions = extensions + ['ps1', 'xml', 'bat', 'cs', 'psd1', 'ps2', 'psc1', 'psc2', 'vbs', 'vba']

    if current_depth >= depth_limit:
        return

    files = []
    dirs = []

    contents = con.listPath(share, f"{path}/*")
    
    for content in contents:
        content_name = content.get_longname()

        if content_name in ['.', ".."]:
            continue
        
        if content.is_directory():
            dirs.append(content_name)
        else:
            files.append({'file_object': content, 'longname': content_name, 'size': content.get_filesize(), 'path': path})

    # analyze files for extensions, keywords
    if len(files) > 0:
        print(f"[+] Found files")
        
        for file in files:
            print(f"\t\t{file['longname']} {str(file['size'])}")
            check_file(share, id, con, file, extensions, keywords, size_limit)

    # create new crawl_share threads for dirs
    if len(dirs) > 0:
        print(f"[+] Found dirs")

        for dir in dirs:
            print(f"\t\t{dir}")
            crawl_share(share, id, con, extensions, keywords, size_limit, depth_limit, f"{path}/{dir}", current_depth)


def crawl_share(share, id, con, extensions, keywords, size_limit, depth_limit, path, current_depth):
    """
    Performs crawling of a share

    Args:
        share: (share object) The share object to crawl
        id: (int) The share ID
        con: (SMBConnection) SMB connection object
        extensions: (list) List of extensions to check for
        keywords: (list) List of keywords to check for
        size_limit: (int) The maximum file size to scan
        depth_limit: (int) The maximum number of directories to crawl
        path: (string) The current directory path being crawled, used for recursive crawling
        current_depth: (int) The current dept being crawled, used for recursive crawling

    Returns:
        None
    """

    current_depth += 1

    print(f"[*] Crawling share: {share}")
    print(f"[*] Current path: {path}")
    print(f"[*] Current depth: {str(current_depth)} of limit {str(depth_limit)}")

    if current_depth >= depth_limit:
        return

    files = []
    dirs = []

    contents = con.listPath(share, f"{path}/*")
    
    for content in contents:
        content_name = content.get_longname()

        if content_name in ['.', ".."]:
            continue
        
        if content.is_directory():
            dirs.append(content_name)
        else:
            files.append({'file_object': content, 'longname': content_name, 'size': content.get_filesize(), 'path': path})

    # analyze files for extensions, keywords
    if len(files) > 0:
        print(f"[+] Found files")
        
        for file in files:
            print(f"\t\t{file['longname']} {str(file['size'])}")
            check_file(share, id, con, file, extensions, keywords, size_limit)

    # create new crawl_share threads for dirs
    if len(dirs) > 0:
        print(f"[+] Found dirs")

        for dir in dirs:
            print(f"\t\t{dir}")
            crawl_share(share, id, con, extensions, keywords, size_limit, depth_limit, f"{path}/{dir}", current_depth)


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
    parser.add_argument("-u", "--username", help="Domain user username", required=True)
    parser.add_argument("-p", "--password", help="Domain user password", required=True)
    parser.add_argument("-tf", "--targetfile", help="List of targets to share scan, one per line", required=True)
    parser.add_argument("-e", "--extensions", help="Comma seperated list of extensions to search for (ex: xml,txt,.ps1,.xml) (default: xml, txt, ps1, csv)", required=False)
    parser.add_argument("-k", "--keywords", help="Comma seperated list of keywords to search for (ex: password, username, ssn), searches file contents if it matches size and extension requirements, searches file names (default: pass, password, username, user, confidential, sensitive)", required=False)
    parser.add_argument("-sl", "--sizelimit", help="Size limit for searched files, in MB (ex: 5) (default: 5)", required=False)
    parser.add_argument("-dl", "--depthlimit", help="Depth limit for directory searching (default: 3)", required=False)
    parser.add_argument("-st", "--sleeptime", help="Time to sleep between target (default: 10 seconds)", required=False)
    parser.add_argument("-sv", "--sysvol", help="If a SYSVOL share is targeted, perform thorough inspections (default: False)", required=False)
    # TODO: parser.add_argument("-ad", "--advancedsearch", help="Perform advanced searches using regex on file contents, file names (default: False)", required=False)
    parser.add_argument("-di", "--discovery", help="Discovery mode. Only find available shares, don't spider (default: False)", required=False)
    args = parser.parse_args()

    user = args.username
    password = args.password
    domain = args.domain
    extensions = ["csv","log", "dat", "xml", "txt", "xls", "docx", "md", "pdf", "ps1"] 
    keywords = ["password", "username"]
    size_limit = 5
    depth_limit = 2
    sleeptime = 10
    path = '.'
    current_depth = 0

    try:
        with open(args.targetfile) as f:
            lines = f.readlines()

        targets = [x.strip() for x in lines]
    except Exception as e:
        print(f"[-] Error reading list of targets: {str(e)}")
        sys.exit(1)

    try:
        if args.sizelimit:
            size_limit = int(args.sizelimit)
    except:
        pass

    try:
        if args.depthlimit:
            depth_limit = int(args.depthlimit)
    except:
        pass

    try:
        if args.sleeptime:
            sleeptime = int(args.sleeptime)
    except:
        pass

    if args.discovery:
        discovery = True
    else:
        discovery = False

    if args.sysvol:
        sysvol = True
    else:
        sysvol = False

    for target in targets:
        print(f"\n[*] Crawling target {target}")

        try:
            con = SMBConnection(target, target, sess_port=445)
            con.login(user, password, domain)
        except Exception as e:
            print(f"[-] Error accessing target: {str(e)}")
            continue

        shares = list_shares(con)

        if discovery:
            for item in shares:
                print(f"[+] Found share: {item}")

        shares_dicts = check_share_access(shares, con)

        if discovery:
            continue

        for share_dict in shares_dicts:
            if sysvol and share_dict['name'] == 'SYSVOL':
                sysvol_crawl(share_dict['name'], share_dict['id'], con, extensions, keywords, size_limit, depth_limit + 3, path, current_depth)
            else:
                crawl_share(share_dict['name'], share_dict['id'], con, extensions, keywords, size_limit, depth_limit, path, current_depth)
            
        time.sleep(sleeptime)


if __name__ == "__main__":
    main()
