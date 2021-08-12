# Buffalo 
A Python 3 script to execute dictionary/wordlist attacks on a target SSH server using two text files as input. Authored for the purposes of my Intel technical screening.

### Installation  
This script depends on [Paramiko](http://www.paramiko.org/) and [Colorama](https://pypi.org/project/colorama/).
Install the dependencies via `pip install -r requirements.txt` or `pip3 install -r requirements.txt`.

## Usage  

#### Default Settings
Port 22 with no attempt limit, or lockout period  
`python3 buffalo.py localhost users.txt passwords.txt`  

#### Higher Thread Count  
Default number of threads is *100*, this amount can be raised or lowered using the *thread* flag.  
`python3 buffalo.py localhost users.txt passwords.txt --threads 200 `

#### Non Standard Port
Specify service on port *2222*  
`python3 buffalo.py localhost users.txt passwords.txt --port 2222`  

#### Max Attempts in Lockout Window  
Most systems have some sort of attempt limit per account in a ceratin time frame. To fly under this limit the number of attempts per account can be limited via the *--max_attempts* and *--lockout_period* flags. For example, to limit *3* attempts per account in a *15* minute period.  
`python3 buffalo.py localhost users.txt passwords.txt --max_attempts 3 --lockout_period 15 `

### Help Docs
```
[$] python3 buffalo.py -h                                                                                         [12:39:53]
usage: buffalo.py [-h] [--port [PORT]] [--max_attempts [MAX_ATTEMPTS]] [--lockout_period [LOCKOUT_PERIOD]]
                  [--threads [THREADS]]
                  target users passwords

Quick SSH brute force script for Red Team @Intel.

positional arguments:
  target                Target IP or hostname.
  users                 Username file, one username per line.
  passwords             Password file, one password per line.

optional arguments:
  -h, --help            show this help message and exit
  --port [PORT]         SSH port. DEFAULT 22.
  --max_attempts [MAX_ATTEMPTS]
                        Max attempts per account within the lockout window. DEFAULT unlimited.
  --lockout_period [LOCKOUT_PERIOD]
                        Length of the lockout window in minutes. DEFAULT 0.
  --threads [THREADS]   Thread count. DEFAULT 100.
```


## Future Work  
Here's a brief list of things I think would be cool to implement in the future.  
* Lots of user interface improvements, display total credentials attempted, display elapsed time, estimated time to completion, etc.
* Add the ability for the user to toggle the *cool down* period during runtime if it's clearly too short or long for a particular server.
* Add an option to kill all threads when any valid credentials are found, rather than keep trying the other user accounts. 
* An option to open up an interactive shell if valid credentials are found, via the Paramiko client's `invoke_shell`.
* Various options that harness `exec_command` if valid creds are found. Brainstormed ideas below.
  * Download and execute C2 stager.
  * Run host or network enumeration scripts.
  * All things...
* Proxies, tunneling...?
