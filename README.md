# mod_bouncer

`mod_bouncer` is a module for Apache 2.4 that blocks incoming requests containing specific patterns in their URL path. Blocked requests can be sent to a log file, enabling external tools (e.g. `fail2ban`) to set firewall rules to completely block attackers or generate alerts.

## Build and install

You need the [APXS](https://httpd.apache.org/docs/2.4/programs/apxs.html) tool to build and install the module.

Use the script `build.sh` to build the module and `install.sh` to install and activate the module in your Apache installation. Make sure you have the necessary privileges to use `install.sh`.

```
# ./build.sh
# sudo ./install.sh
```

You need to restart the Apache service after the installation.

## Configuration

`mod_bouncer` offers the following directives to be used in the server configuration.
* **BouncerEngine**: Enable (`on`) or disable (`off`) the `mod_bouncer`. This directive must appear before any other.
* **BouncerPattern**: Add one or more patterns to the ruleset. Patterns must be separated with spaces and each pattern is a string with three one more characters. Valid characters are (see section [2. Characters](https://www.rfc-editor.org/rfc/rfc3986#section-2) of [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)): `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`, `:`, `/`, `?`, `#`, `[`, `]`, `@`, `!`, `$`, `&`, `'`, `(`, `)`, `*`, `+`, `,`, `;`, `%`, and `=`. You can also use `^` as the first character to indicate the pattern must appear at the beginning of the URL path. This directive can be used multiple times.
* **BouncerTrustedProxy**: List of IP addresses of the trusted proxies. This is used to discover the actual address of the client when the Apache is behind one or more proxies. This directive can be used multiple times. For more information, see [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) at MDN. The discovered address is used in the module log.
* **BouncerLog**: Path to the log file. Make sure the Apache process has the necessary privilege to write to the file. This log contains entries for every blocked request and can be monitored by tools (e.g. `fail2ban`) to change firewall rules or generate alerts.

## Example

Example of server at `10.0.1.25` that receives requests through a proxy at `10.0.1.24`:

```
<VirtualHost 10.0.1.25:80>

    ...

    <IfModule mod_bouncer.c>
            BouncerEngine on
            BouncerPattern .git ^/wp-admin
            BouncerPattern ^/xmlrpc
            BouncerLog /run/mod_bouncer.log
            BouncerTrustedProxy 10.0.1.24
    </IfModule>

    ...

</VirtualHost>
```
Example of output for blocked request in `/run/mod_bouncer.log`. The address `200.10.3.22` in the example was extracted from `X-Forwarded-For` header since `10.0.1.24` is a trusted proxy.

```
2022-05-10T09:28:40-0400 [BLOCKED] 10.0.1.24 200.10.3.22 GET "/wp-admin/ps" 404 "" "curl/7.68.0"

```
