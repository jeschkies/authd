# authd(2)
`authd` is an authentication daemon that uses a secret to authenticate and saves an authentication token into a file.

## Usage

Simply start the daemon with `authd <private_key> <token>`. The program will fetch a new authentication token
and save it to `token`. Delete the token if you want to force a refresh.

You client should read the toke form the token file and wait if there is no file yet.

## Options

* `--cert` Optional location of a CA certificate file for SSL connections. It defaults to `.ssl/ca-bundle.crt`.
* `--endpoint` The authentication endpoint to use. It defaults to `https://master.mesos`.

The program uses [env_logger](https://github.com/sebasmagri/env_logger). You can set the log level via `RUST_LOG=info`.
