cbcerthelper
============
Utility and library for the purpose of assisting in creating certificates and client certificates for use in authentication against Couchbase Server during development/testing.

Using as an application
------------------------
Building is the usual go thing: `go build -o cbcerthelper ./cmd/cbcerthelper/main.go`.

What it does:
    
    * Creates a root certificate and key
    * Creates a node certificate, certificate request, and key for each node provided
    * Copies the node certificate and key to the node over ssh/scp
    * Uploads the root certificate to the node and reloads the certificate
    * Creates a client certificate that can be used to auth against nodes
    * Writes out all the certificates and keys to disk

What it might do:

    * If it fails then it might leave your cluster in a weird state where some nodes have certificates and others don't

What it won't do:

    * Any attempt at recovery if it fails at any step
    
Usage
-----
Configuration of the executable is done via a config file (it'll look for `$HOME/.cbcerthelper.toml`) or cli flags.
Parameters are the same in both config file and cli and are:

| Name | Type | Description | Example |   |
|---|---|---|---|---|
| config | string  | Path to config file | `./.cbcerthelper.toml` |   |
| http-user | string  | Username to use for auth against Couchbase Server | `MyAdminUser` |   |
| http-pass | string  | Password to use for auth against Couchbase Server | `MyAdminPass` |   |
| ssh-user | string  | Username to use for ssh access to nodes hosting Couchbase Server | `gary` |   |
| ssh-pass | string  | Password to use for ssh access to nodes hosting Couchbase Server | `garyspassword` |   |
| cert-user | string  | The username for the user that will be authenticating with this client certificate | `dave` |   |
| cert-email | string  | The email for the user that will be authenticating with this client certificate | `dave@davescompany.com` |   |
