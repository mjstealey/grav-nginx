# grav-nginx
Debian [Stretch](https://hub.docker.com/_/debian/) Docker based [Grav](https://getgrav.org) installation using Nginx

**WORK IN PROGRESS**:

- [x] Basic implementation in Docker
- [x] Extend volume mount to local `html` directory
- [x] Allow UID/GID setting within container for host user permissions on mounted volumes
- [x] SSL integration - self generated certs
- [ ] LetsEncrypt documentation

## Supported tags and respective Dockerfile links

Tags available in Dockerhub: [mjstealey/grav-nginx](https://hub.docker.com/r/mjstealey/grav-nginx/)

- 1.3.0-rc.5, latest ([1.3.0-rc.5/Dockerfile](https://github.com/mjstealey/grav-nginx/blob/master/1.3.0-rc.5/Dockerfile))

### Pull image from dockerhub

```bash
docker pull mjstealey/grav-nginx:latest
```

### Usage:

**Example 1.** Deploy with default configuration over http

```bash
docker run --name grav -p 80:80 mjstealey/grav-nginx:latest
```
- **NOTE**: Generally the `-d` flag would be used in the above call to daemonize the process

```bash
$ docker run --name grav -p 80:80 mjstealey/grav-nginx:latest
Unable to find image 'mjstealey/grav-nginx:latest' locally
latest: Pulling from mjstealey/grav-nginx
c75480ad9aaf: Pull complete
58434b614b6f: Pull complete
71377105a799: Pull complete
595da19ffe38: Pull complete
74b64a239d34: Pull complete
d966c11a03be: Pull complete
Digest: sha256:961b66eb7bbc40566885b4eb187d6b5b1bcee28008db95da004fcff8a381c056
Status: Downloaded newer image for mjstealey/grav-nginx:latest
usermod: no changes
Starting nginx: nginx.
Archive:  /grav-admin-v1.3.0-rc.5.zip
   creating: grav-admin/
  inflating: grav-admin/index.php
   creating: grav-admin/bin/
  inflating: grav-admin/bin/composer.phar
  inflating: grav-admin/bin/plugin
  inflating: grav-admin/bin/grav
  inflating: grav-admin/bin/gpm
  inflating: grav-admin/CODE_OF_CONDUCT.md
  
...

deleting grav-admin/CONTRIBUTING.md
deleting grav-admin/CODE_OF_CONDUCT.md
deleting grav-admin/CHANGELOG.md
deleting grav-admin/.htaccess
deleting grav-admin/

sent 20,348,404 bytes  received 58,553 bytes  13,604,638.00 bytes/sec
total size is 20,137,437  speedup is 0.99
/docker-entrypoint.sh: line 137: /subfolder/index.php: No such file or directory
Restarting nginx: nginx.
Restarting PHP 7.0 FastCGI Process Manager: php-fpm7.0.
Reloading nginx configuration: nginx.
```

The running site can be found at [http://localhost](http://localhost).

- On first use the user will be redirected to [http://localhost/admin](http://localhost/admin) to register an Admin User for the installation.
![Grav Register Admin User](https://user-images.githubusercontent.com/5332509/27988518-752da2e0-63f1-11e7-8731-9e6e185536c8.png)

**Example 2.** Using `docker-compose.yml` to deploy a locally built container with **(1.)** Local volume mount, **(2.)** SSL using self generated certificates

An example `docker-compose.yml` file is included in the repository to demonstrate how to use the self generated SSL certificates. This is useful for development, but should not be used in prodcution as the generated certificates are not signed by any authority.

```yaml
version: '3.3'                         # Varies based on the installed docker version
services:
  grav-nginx:
    build:                             # Local build definition
      context: ./1.3.0-rc.5            # Optionally use image: call
      dockerfile: Dockerfile
    container_name: grav
    environment:
      - USE_SSL=true                   # Set to use SSL
      - USE_SELF_GEN_CERT=true         # Set to generate self signed certs
    volumes:
      - "./html:/home/grav/www/html"   # Set to share local volume named html
    ports:
      - "80:80"                        # Serve http on port 80
      - "443:443"                      # Serve https on port 443
```

The user can build and deploy this container as follows:

```bash
$ cd /PATH/TO/grav-nginx/
$ docker-compose build
$ docker-compose up
```
- **NOTE**: Generally the `-d` flag would be used in the above call to daemonize the process

```bash
$ docker-compose build
Building grav-nginx
Step 1/23 : FROM debian:stretch
stretch: Pulling from library/debian
c75480ad9aaf: Already exists
Digest: sha256:7d067f77d2ae5a23fe6920f8fbc2936c4b0d417e9d01b26372561860750815f0
Status: Downloaded newer image for debian:stretch
 ---> a2ff708b7413
Step 2/23 : MAINTAINER Michael J. Stealey <michael.j.stealey@gmail.com>
 ---> Running in 329135b249a5
 ---> 014e0fc2a564
Removing intermediate container 329135b249a5
...
Removing intermediate container d675a5afd636
Step 23/23 : CMD grav
 ---> Running in b2fada24de9b
 ---> 76792ba39d05
Removing intermediate container b2fada24de9b

Successfully built 76792ba39d05
Successfully tagged gravnginx_grav-nginx:latest
```

```bash
$ docker-compose up -d
Creating grav ...
Creating grav ... done
```

After a few moments the running site can be found at [https://localhost](https://localhost).

- On first use the user will be asked if they wish to proceed to an "unsafe" https site, and when given the OK, redirected to [https://localhost/admin](https://localhost/admin) to register an Admin User for the installation.

![https-ssl-cert-warning](https://user-images.githubusercontent.com/5332509/27988520-7de8ff60-63f1-11e7-9642-0a5a45d9a90c.png)

![https-grav-admin](https://user-images.githubusercontent.com/5332509/27988522-83b1402e-63f1-11e7-9919-5c0d7c7de4f3.png)

All of the grav site related files will now be stored in the local `html` directory of the checked out repository.

```bash
$ ls ./html
CHANGELOG.md       README.md          cache              index.php          robots.txt         vendor
CODE_OF_CONDUCT.md assets             composer.json      local.dev.crt      system             webserver-configs
CONTRIBUTING.md    backup             composer.lock      local.dev.key      tmp
LICENSE.txt        bin                images             logs               user
```

The two files named `local.dev.crt` and `local.dev.key` are the self generated SSL certificate and key pair. These are moved to locations `/etc/ssl/certs/server.crt` and `/etc/ssl/private/server.key` for use by Nginx in the **grav** container by the `docker-entrypoint.sh` script at runtime.
