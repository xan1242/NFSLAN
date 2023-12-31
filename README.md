# NFS LAN Server Launcher

A very simple console launcher for the server.dll found in Underground 2 and Most Wanted.

## Usage

- Copy server.dll and server.cfg from the game next to NFSLAN binary (NOTE: servers are different between MW and UG2!)

- Configure the server in `server.cfg`

- Launch NFSLAN like this: `nfslan YourServerName` where `YourServerName` should be self-explanatory

## Server configuration

Currently a lot of settings are left undocumented. 

However, the most important one would be the port, which you can simply define like this: `PORT=9900`

`%%bind` simply binds the address to the available local range, while inputting the IP directly makes it use directly.

There are also `%%dns`, `%%host` (for host names) and a few other keys found within `0x10029AF0` of MW's server.dll (including if statements, includes, variables, etc.)

`ADDR`  - sets the listen address - this is what is sent to clients as the "slave" address, so disregard what the config comment says - it most certainly communicates with this address

`MADDR` & `MPORT` - probably sets master server address & port

`RADDR` & `RPORT` - probably sets the redirector address & port

`LADDR` & `LPORT` - probably sets the lobby address & port

`AADDR` & `APORT` - probably sets the account server address & port

`LOGCONNECTIONS` - when set to 1, it enables connection logs to the console from the redirector

`log.level` - sets the verbosity of logging. 4 by default, goes up to 10 (TODO - check this)

`log.categoryMask` - self explanatory

`PERIP` - unknown

`RXDEL` - unknown

`RXLEN` - unknown

`scheduler.type` - is set to `select` by default. Not sure if there are any other options available

`scheduler.maxFd` - unknown

`scheduler.maxEvents` - unknown

There's a lot more that I've missed. This server is pretty large, actually, with enough code to probably run the entire Online mode of the games again.

## Patches

This launcher also automatically patches the server to allow online gameplay.

This also requires some client-side patches.

- SKU - this tag needs to return the external IP of the client in order to determine an online connection

- Client needs to host a UDP server to respond to a local challenge to determine if it's actually local to the server itself on port 9901 - this happens if the address returned via the SKU tag and the connection addresses are different

- UDP bind for the game (not lobby) client needs to be skipped

- Optionally, the returned server IP of the slave server should be ignored client-side as well and just use the same public one that it initiates the connection with

## TODO

- Document `server.cfg` entirely
- Figure out LAN redirector completely (in conjunction with client-side patches) - currently players can either play online or local, not mixed. (Only 1 local player is working)
