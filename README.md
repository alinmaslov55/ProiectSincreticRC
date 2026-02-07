# TESTING Students-Server Simulator

## Project Structure

ProjectFolder/
├── certs/              # SSL Certificates (server.crt, server.key)
├── common/             # Shared logic
│   ├── protocol.h      # Packet structures & constants
│   ├── crypto.c        # OpenSSL wrappers
│   └── crypto.h
├── client/             # Student Terminal implementation
│   ├── main.c
│   └── ui.c
├── server/             # Proctor Node implementation
│   ├── main.c
│   ├── db_manager.c    # Mock database for students/exams
│   └── engine.c        # Scheduling & state logic
├── build/              # Compiled binaries
└── Makefile            # Build configuration

## Creare Chei

```sh
ngp@Ubuntu:~/Added/Universitate/ProiectSincreticRC/certs$ openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
...+.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+...+........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.....+......+......+...+.+...+..+......+...+......+..................+......+.+........+...+............................+..............................+..+...+.......+..+.+......+.....+....+.........+.....+...+.........+.+..+.............+..+...+...............+.............+..+...+.......+............+..+...+.+..+...+.........+.......+...+............+.....+...+..........+..+.+............+.................+..........+...............+......+............+...+.........+.....+..........+...+...........+......+.........+......+...+...............+.+..+.............+.....+.+...+............+........+.+..+..................+............+............+...+...............+..........+...+.........+..+.+........+.+.....+......+...................+...+....................+.+..+..................+................+.........+......+......+...+.....+...................+..+.............+.....+.+......+...............+......+..............+..........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
...+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..+........+...................+........+...+.+...+..+.............+...+..+.......+...............+......+..+...+..........+...+.....+......+......+.......+..+.+........+......+.........+....+..+...+.+..+....+...........+.......+...+..+.+..+...+.+........+.+...........+...+.......+......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*...+.....+.+..+...+...+.......+..+................+...........+......+.............+.........+...+.....+...+.......+..............+...+...+....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:RO
State or Province Name (full name) [Some-State]:Timis
Locality Name (eg, city) []:Timisoara
Organization Name (eg, company) [Internet Widgits Pty Ltd]:UPT
Organizational Unit Name (eg, section) []:INFO
Common Name (e.g. server FQDN or YOUR name) []:Alin
Email Address []:maslovalin55@gmail.com


ngp@Ubuntu:~/Added/Universitate/ProiectSincreticRC/certs$ chmod 600 certs/server.key
```