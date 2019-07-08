# authd(2)
`authd` is an authentication daemon that uses a secret to authenticate and saves an authentication token into a file.

## Usage

Simply start the daemong with `authd [PRIVATE KEY] [TOKEN LOCATION]`. The program will fetch a new authentication token
and save it to `TOKEN LOCATION`. Delete the token if you want to force a refresh.

## Options

* `--cert` Optional location of a CA certificate file for SSL connections. It defaults to `.ssl/ca-bundle.crt`.
* `--endpoint` The authentication endpoint to use. It defaults to `https://master.mesos`.
