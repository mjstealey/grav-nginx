#!/usr/bin/env bash

set -e

_update_uid_gid() {
  # default: uid=1000(grav) gid=1000(grav) groups=1000(grav)
  groupmod -g ${GID_GRAV} grav
  usermod -u ${UID_GRAV} grav
  chown -R grav /home/grav/
}

_grav_conf () {
  local OUTFILE=/etc/php/7.0/fpm/pool.d/grav.conf
  if [[ -e /etc/php/7.0/fpm/pool.d/www.conf ]]; then
    rm -f /etc/php/7.0/fpm/pool.d/www.conf
  fi
  echo "[grav]" > $OUTFILE
  echo "" >> $OUTFILE
  echo "user = grav" >> $OUTFILE
  echo "group = grav" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "listen = /run/php/php7.0-fpm.sock" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "listen.owner = www-data" >> $OUTFILE
  echo "listen.group = www-data" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "pm = dynamic" >> $OUTFILE
  echo "pm.max_children = 5" >> $OUTFILE
  echo "pm.start_servers = 2" >> $OUTFILE
  echo "pm.min_spare_servers = 1" >> $OUTFILE
  echo "pm.max_spare_servers = 3" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "chdir = /" >> $OUTFILE
}

_nginx_conf () {
  local OUTFILE=/etc/nginx/nginx.conf
  echo "user www-data;" > $OUTFILE
  echo "worker_processes auto;" >> $OUTFILE
  echo "worker_rlimit_nofile 8192; # should be bigger than worker_connections" >> $OUTFILE
  echo "pid /run/nginx.pid;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "events {" >> $OUTFILE
  echo "    use epoll;" >> $OUTFILE
  echo "    worker_connections 8000;" >> $OUTFILE
  echo "    multi_accept on;" >> $OUTFILE
  echo "}" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "http {" >> $OUTFILE
  echo "    sendfile on;" >> $OUTFILE
  echo "    tcp_nopush on;" >> $OUTFILE
  echo "    tcp_nodelay on;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    keepalive_timeout 30; # longer values are better for each ssl client, but take up a worker connection longer" >> $OUTFILE
  echo "    types_hash_max_size 2048;" >> $OUTFILE
  echo "    server_tokens off;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # maximum file upload size" >> $OUTFILE
  echo "    # update 'upload_max_filesize' & 'post_max_size' in /etc/php5/fpm/php.ini accordingly" >> $OUTFILE
  echo "    client_max_body_size 32m;" >> $OUTFILE
  echo "    # client_body_timeout 60s; # increase for very long file uploads" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # set default index file (can be overwritten for each site individually)" >> $OUTFILE
  echo "    index index.html;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # load MIME types" >> $OUTFILE
  echo "    include mime.types; # get this file from https://github.com/h5bp/server-configs-nginx" >> $OUTFILE
  echo "    default_type application/octet-stream; # set default MIME type" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # logging" >> $OUTFILE
  echo "    access_log ${NGINX_ACCESS_LOG};" >> $OUTFILE
  echo "    error_log ${NGINX_ERROR_LOG};" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # turn on gzip compression" >> $OUTFILE
  echo "    gzip on;" >> $OUTFILE
  echo "    gzip_disable \"msie6\";" >> $OUTFILE
  echo "    gzip_vary on;" >> $OUTFILE
  echo "    gzip_proxied any;" >> $OUTFILE
  echo "    gzip_comp_level 5;" >> $OUTFILE
  echo "    gzip_buffers 16 8k;" >> $OUTFILE
  echo "    gzip_http_version 1.1;" >> $OUTFILE
  echo "    gzip_min_length 256;" >> $OUTFILE
  echo "    gzip_types" >> $OUTFILE
  echo "        application/atom+xml" >> $OUTFILE
  echo "        application/javascript" >> $OUTFILE
  echo "        application/json" >> $OUTFILE
  echo "        application/ld+json" >> $OUTFILE
  echo "        application/manifest+json" >> $OUTFILE
  echo "        application/rss+xml" >> $OUTFILE
  echo "        application/vnd.geo+json" >> $OUTFILE
  echo "        application/vnd.ms-fontobject" >> $OUTFILE
  echo "        application/x-font-ttf" >> $OUTFILE
  echo "        application/x-web-app-manifest+json" >> $OUTFILE
  echo "        application/xhtml+xml" >> $OUTFILE
  echo "        application/xml" >> $OUTFILE
  echo "        font/opentype" >> $OUTFILE
  echo "        image/bmp" >> $OUTFILE
  echo "        image/svg+xml" >> $OUTFILE
  echo "        image/x-icon" >> $OUTFILE
  echo "        text/cache-manifest" >> $OUTFILE
  echo "        text/css" >> $OUTFILE
  echo "        text/plain" >> $OUTFILE
  echo "        text/vcard" >> $OUTFILE
  echo "        text/vnd.rim.location.xloc" >> $OUTFILE
  echo "        text/vtt" >> $OUTFILE
  echo "        text/x-component" >> $OUTFILE
  echo "        text/x-cross-domain-policy;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # disable content type sniffing for more security" >> $OUTFILE
  echo "    add_header \"X-Content-Type-Options\" \"nosniff\";" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # force the latest IE version" >> $OUTFILE
  echo "    add_header \"X-UA-Compatible\" \"IE=Edge\";" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # enable anti-cross-site scripting filter built into IE 8+" >> $OUTFILE
  echo "    add_header \"X-XSS-Protection\" \"1; mode=block\";" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # include virtual host configs" >> $OUTFILE
  echo "    include sites-enabled/*;" >> $OUTFILE
  echo "}" >> $OUTFILE
}

_http_grav_site () {
  local OUTFILE=/etc/nginx/sites-available/grav
  local OUTFILE_SYMLINK=/etc/nginx/sites-enabled/grav
  echo "server {" > $OUTFILE
  echo "  #listen 80;" >> $OUTFILE
  echo "  index index.html index.php;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - Server Info" >> $OUTFILE
  echo "  root /home/grav/www/html;" >> $OUTFILE
  echo "  server_name ${FQDN_OR_IP};" >> $OUTFILE
  echo "  ## End - Server Info" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - Index" >> $OUTFILE
  echo "  # for subfolders, simply adjust the rewrite:" >> $OUTFILE
  echo "  # to use `/subfolder/index.php`" >> $OUTFILE
  echo "  location / {" >> $OUTFILE
  echo "      try_files \$uri \$uri/ /index.php?_url=\$uri;" >> $OUTFILE
  echo "  }" >> $OUTFILE
  echo "  ## End - Index" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - PHP" >> $OUTFILE
  echo "  location ~ \\.php$ {" >> $OUTFILE
  echo "      # Choose either a socket or TCP/IP address" >> $OUTFILE
  echo "      fastcgi_pass unix:/run/php/php7.0-fpm.sock;" >> $OUTFILE
  echo "      # fastcgi_pass 127.0.0.1:9000;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "      fastcgi_split_path_info ^(.+\.php)(/.+)$;" >> $OUTFILE
  echo "      fastcgi_index index.php;" >> $OUTFILE
  echo "      include fastcgi_params;" >> $OUTFILE
  echo "      fastcgi_param SCRIPT_FILENAME \$document_root/\$fastcgi_script_name;" >> $OUTFILE
  echo "  }" >> $OUTFILE
  echo "  ## End - PHP" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - Security" >> $OUTFILE
  echo "  # deny all direct access for these folders" >> $OUTFILE
  echo "  location ~* /(.git|cache|bin|logs|backups)/.*$ { return 403; }" >> $OUTFILE
  echo "  # deny running scripts inside core system folders" >> $OUTFILE
  echo "  location ~* /(system|vendor)/.*\\.(txt|xml|md|html|yaml|php|pl|py|cgi|twig|sh|bat)$ { return 403; }" >> $OUTFILE
  echo "  # deny running scripts inside user folder" >> $OUTFILE
  echo "  location ~* /user/.*\\.(txt|md|yaml|php|pl|py|cgi|twig|sh|bat)$ { return 403; }" >> $OUTFILE
  echo "  # deny access to specific files in the root folder" >> $OUTFILE
  echo "  location ~ /(LICENSE|composer.lock|composer.json|nginx.conf|web.config|htaccess.txt|\\.htaccess) { return 403; }" >> $OUTFILE
  echo "  ## End - Security" >> $OUTFILE
  echo "}" >> $OUTFILE
  rm -f $OUTFILE_SYMLINK
  ln -s $OUTFILE $OUTFILE_SYMLINK
}

_https_grav_site () {
  local OUTFILE=/etc/nginx/sites-available/grav
  local OUTFILE_SYMLINK=/etc/nginx/sites-enabled/grav
  if $REDIRECT_HTTP_TO_HTTPS; then
    echo "# redirect http to https" >> $OUTFILE
    echo "server {" >> $OUTFILE
    echo "  listen [::]:80;" >> $OUTFILE
    echo "  listen 80;" >> $OUTFILE
    echo "  server_name ${FQDN_OR_IP};" >> $OUTFILE
    echo "" >> $OUTFILE
    echo "  return 301 https://${FQDN_OR_IP}$request_uri;" >> $OUTFILE
    echo "}" >> $OUTFILE
    echo "# serve website" >> $OUTFILE
    echo "server {" >> $OUTFILE
    echo "  listen [::]:443 ssl;" >> $OUTFILE
    echo "  listen 443 ssl;" >> $OUTFILE
    echo "" >> $OUTFILE
  else
    echo "# serve website" > $OUTFILE
    echo "server {" >> $OUTFILE
    echo "  listen [::]:80;" >> $OUTFILE
    echo "  listen 80;" >> $OUTFILE
    echo "  listen [::]:443 ssl;" >> $OUTFILE
    echo "  listen 443 ssl;" >> $OUTFILE
    echo "" >> $OUTFILE
  fi
  echo "   # add ssl cert & options" >> $OUTFILE
  echo "   include ssl.conf;" >> $OUTFILE
  echo "  index index.html index.php;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - Server Info" >> $OUTFILE
  echo "  root /home/grav/www/html;" >> $OUTFILE
  echo "  server_name ${FQDN_OR_IP};" >> $OUTFILE
  echo "  ## End - Server Info" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - Index" >> $OUTFILE
  echo "  # for subfolders, simply adjust the rewrite:" >> $OUTFILE
  echo "  # to use '/subfolder/index.php'" >> $OUTFILE
  echo "  location / {" >> $OUTFILE
  echo "      try_files \$uri \$uri/ /index.php?_url=\$uri;" >> $OUTFILE
  echo "  }" >> $OUTFILE
  echo "  ## End - Index" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - PHP" >> $OUTFILE
  echo "  location ~ \\.php$ {" >> $OUTFILE
  echo "      # Choose either a socket or TCP/IP address" >> $OUTFILE
  echo "      fastcgi_pass unix:/run/php/php7.0-fpm.sock;" >> $OUTFILE
  echo "      # fastcgi_pass 127.0.0.1:9000;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "      fastcgi_split_path_info ^(.+\.php)(/.+)$;" >> $OUTFILE
  echo "      fastcgi_index index.php;" >> $OUTFILE
  echo "      include fastcgi_params;" >> $OUTFILE
  echo "      fastcgi_param SCRIPT_FILENAME \$document_root/\$fastcgi_script_name;" >> $OUTFILE
  echo "  }" >> $OUTFILE
  echo "  ## End - PHP" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  ## Begin - Security" >> $OUTFILE
  echo "  # deny all direct access for these folders" >> $OUTFILE
  echo "  location ~* /(.git|cache|bin|logs|backups)/.*$ { return 403; }" >> $OUTFILE
  echo "  # deny running scripts inside core system folders" >> $OUTFILE
  echo "  location ~* /(system|vendor)/.*\\.(txt|xml|md|html|yaml|php|pl|py|cgi|twig|sh|bat)$ { return 403; }" >> $OUTFILE
  echo "  # deny running scripts inside user folder" >> $OUTFILE
  echo "  location ~* /user/.*\\.(txt|md|yaml|php|pl|py|cgi|twig|sh|bat)$ { return 403; }" >> $OUTFILE
  echo "  # deny access to specific files in the root folder" >> $OUTFILE
  echo "  location ~ /(LICENSE|composer.lock|composer.json|nginx.conf|web.config|htaccess.txt|\\.htaccess) { return 403; }" >> $OUTFILE
  echo "  ## End - Security" >> $OUTFILE
  echo "}" >> $OUTFILE
  rm -f $OUTFILE_SYMLINK
  ln -s $OUTFILE $OUTFILE_SYMLINK
}

_ssl_conf () {
  local OUTFILE=/etc/nginx/ssl.conf
  echo "# set the paths to your cert and key files here" > $OUTFILE
  echo "ssl_certificate ${SSL_CERTIFICATE};" >> $OUTFILE
  echo "ssl_certificate_key ${SSL_CERTIFICATE_KEY};" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA;" >> $OUTFILE
  echo "ssl_prefer_server_ciphers on;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "ssl_session_cache shared:SSL:10m; # a 1mb cache can hold about 4000 sessions, so we can hold 40000 sessions" >> $OUTFILE
  echo "ssl_session_timeout 24h;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "# Use a higher keepalive timeout to reduce the need for repeated handshakes" >> $OUTFILE
  echo "keepalive_timeout 300s; # up from 75 secs default" >> $OUTFILE
  echo "" >> $OUTFILE
  if $USE_PRELOAD; then
    echo "# submit domain for preloading in browsers at: https://hstspreload.appspot.com" >> $OUTFILE
    echo "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload;\";" >> $OUTFILE
    echo "" >> $OUTFILE
  fi
  if $USE_OCSP_STAPLING; then
    echo "# OCSP stapling" >> $OUTFILE
    echo "# nginx will poll the CA for signed OCSP responses, and send them to clients so clients don't make their own OCSP calls." >> $OUTFILE
    echo "# see https://sslmate.com/blog/post/ocsp_stapling_in_apache_and_nginx on how to create the chain+root" >> $OUTFILE
    echo "ssl_stapling on;" >> $OUTFILE
    echo "ssl_stapling_verify on;" >> $OUTFILE
    echo "ssl_trusted_certificate /etc/ssl/certs/domain.tld.chain+root.crt;" >> $OUTFILE
    echo "resolver 8.8.8.8 8.8.4.4 216.146.35.35 216.146.36.36 valid=60s;" >> $OUTFILE
    echo "resolver_timeout 2s;" >> $OUTFILE
  fi
}

_mime_types () {
  local OUTFILE=/etc/nginx/mime.types
  echo "types {" > $OUTFILE
  echo "" >> $OUTFILE
  echo "  # Data interchange" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    application/atom+xml                  atom;" >> $OUTFILE
  echo "    application/json                      json map topojson;" >> $OUTFILE
  echo "    application/ld+json                   jsonld;" >> $OUTFILE
  echo "    application/rss+xml                   rss;" >> $OUTFILE
  echo "    application/vnd.geo+json              geojson;" >> $OUTFILE
  echo "    application/xml                       rdf xml;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  # JavaScript" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # Normalize to standard type." >> $OUTFILE
  echo "    # https://tools.ietf.org/html/rfc4329#section-7.2" >> $OUTFILE
  echo "    application/javascript                js;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  # Manifest files" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    application/manifest+json             webmanifest;" >> $OUTFILE
  echo "    application/x-web-app-manifest+json   webapp;" >> $OUTFILE
  echo "    text/cache-manifest                   appcache;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  # Media files" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    audio/midi                            mid midi kar;" >> $OUTFILE
  echo "    audio/mp4                             aac f4a f4b m4a;" >> $OUTFILE
  echo "    audio/mpeg                            mp3;" >> $OUTFILE
  echo "    audio/ogg                             oga ogg opus;" >> $OUTFILE
  echo "    audio/x-realaudio                     ra;" >> $OUTFILE
  echo "    audio/x-wav                           wav;" >> $OUTFILE
  echo "    image/bmp                             bmp;" >> $OUTFILE
  echo "    image/gif                             gif;" >> $OUTFILE
  echo "    image/jpeg                            jpeg jpg;" >> $OUTFILE
  echo "    image/jxr                             jxr hdp wdp;" >> $OUTFILE
  echo "    image/png                             png;" >> $OUTFILE
  echo "    image/svg+xml                         svg svgz;" >> $OUTFILE
  echo "    image/tiff                            tif tiff;" >> $OUTFILE
  echo "    image/vnd.wap.wbmp                    wbmp;" >> $OUTFILE
  echo "    image/webp                            webp;" >> $OUTFILE
  echo "    image/x-jng                           jng;" >> $OUTFILE
  echo "    video/3gpp                            3gp 3gpp;" >> $OUTFILE
  echo "    video/mp4                             f4p f4v m4v mp4;" >> $OUTFILE
  echo "    video/mpeg                            mpeg mpg;" >> $OUTFILE
  echo "    video/ogg                             ogv;" >> $OUTFILE
  echo "    video/quicktime                       mov;" >> $OUTFILE
  echo "    video/webm                            webm;" >> $OUTFILE
  echo "    video/x-flv                           flv;" >> $OUTFILE
  echo "    video/x-mng                           mng;" >> $OUTFILE
  echo "    video/x-ms-asf                        asf asx;" >> $OUTFILE
  echo "    video/x-ms-wmv                        wmv;" >> $OUTFILE
  echo "    video/x-msvideo                       avi;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # Serving '.ico' image files with a different media type" >> $OUTFILE
  echo "    # prevents Internet Explorer from displaying then as images:" >> $OUTFILE
  echo "    # https://github.com/h5bp/html5-boilerplate/commit/37b5fec090d00f38de64b591bcddcb205aadf8ee" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    image/x-icon                          cur ico;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  # Microsoft Office" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    application/msword                                                         doc;" >> $OUTFILE
  echo "    application/vnd.ms-excel                                                   xls;" >> $OUTFILE
  echo "    application/vnd.ms-powerpoint                                              ppt;" >> $OUTFILE
  echo "    application/vnd.openxmlformats-officedocument.wordprocessingml.document    docx;" >> $OUTFILE
  echo "    application/vnd.openxmlformats-officedocument.spreadsheetml.sheet          xlsx;" >> $OUTFILE
  echo "    application/vnd.openxmlformats-officedocument.presentationml.presentation  pptx;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  # Web fonts" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    application/font-woff                 woff;" >> $OUTFILE
  echo "    application/font-woff2                woff2;" >> $OUTFILE
  echo "    application/vnd.ms-fontobject         eot;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    # Browsers usually ignore the font media types and simply sniff" >> $OUTFILE
  echo "    # the bytes to figure out the font type." >> $OUTFILE
  echo "    # https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern" >> $OUTFILE
  echo "    #" >> $OUTFILE
  echo "    # However, Blink and WebKit based browsers will show a warning" >> $OUTFILE
  echo "    # in the console if the following font types are served with any" >> $OUTFILE
  echo "    # other media types." >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    application/x-font-ttf                ttc ttf;" >> $OUTFILE
  echo "    font/opentype                         otf;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "  # Other" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "    application/java-archive              ear jar war;" >> $OUTFILE
  echo "    application/mac-binhex40              hqx;" >> $OUTFILE
  echo "    application/octet-stream              bin deb dll dmg exe img iso msi msm msp safariextz;" >> $OUTFILE
  echo "    application/pdf                       pdf;" >> $OUTFILE
  echo "    application/postscript                ai eps ps;" >> $OUTFILE
  echo "    application/rtf                       rtf;" >> $OUTFILE
  echo "    application/vnd.google-earth.kml+xml  kml;" >> $OUTFILE
  echo "    application/vnd.google-earth.kmz      kmz;" >> $OUTFILE
  echo "    application/vnd.wap.wmlc              wmlc;" >> $OUTFILE
  echo "    application/x-7z-compressed           7z;" >> $OUTFILE
  echo "    application/x-bb-appworld             bbaw;" >> $OUTFILE
  echo "    application/x-bittorrent              torrent;" >> $OUTFILE
  echo "    application/x-chrome-extension        crx;" >> $OUTFILE
  echo "    application/x-cocoa                   cco;" >> $OUTFILE
  echo "    application/x-java-archive-diff       jardiff;" >> $OUTFILE
  echo "    application/x-java-jnlp-file          jnlp;" >> $OUTFILE
  echo "    application/x-makeself                run;" >> $OUTFILE
  echo "    application/x-opera-extension         oex;" >> $OUTFILE
  echo "    application/x-perl                    pl pm;" >> $OUTFILE
  echo "    application/x-pilot                   pdb prc;" >> $OUTFILE
  echo "    application/x-rar-compressed          rar;" >> $OUTFILE
  echo "    application/x-redhat-package-manager  rpm;" >> $OUTFILE
  echo "    application/x-sea                     sea;" >> $OUTFILE
  echo "    application/x-shockwave-flash         swf;" >> $OUTFILE
  echo "    application/x-stuffit                 sit;" >> $OUTFILE
  echo "    application/x-tcl                     tcl tk;" >> $OUTFILE
  echo "    application/x-x509-ca-cert            crt der pem;" >> $OUTFILE
  echo "    application/x-xpinstall               xpi;" >> $OUTFILE
  echo "    application/xhtml+xml                 xhtml;" >> $OUTFILE
  echo "    application/xslt+xml                  xsl;" >> $OUTFILE
  echo "    application/zip                       zip;" >> $OUTFILE
  echo "    text/css                              css;" >> $OUTFILE
  echo "    text/csv                              csv;" >> $OUTFILE
  echo "    text/html                             htm html shtml;" >> $OUTFILE
  echo "    text/markdown                         md;" >> $OUTFILE
  echo "    text/mathml                           mml;" >> $OUTFILE
  echo "    text/plain                            txt;" >> $OUTFILE
  echo "    text/vcard                            vcard vcf;" >> $OUTFILE
  echo "    text/vnd.rim.location.xloc            xloc;" >> $OUTFILE
  echo "    text/vnd.sun.j2me.app-descriptor      jad;" >> $OUTFILE
  echo "    text/vnd.wap.wml                      wml;" >> $OUTFILE
  echo "    text/vtt                              vtt;" >> $OUTFILE
  echo "    text/x-component                      htc;" >> $OUTFILE
  echo "" >> $OUTFILE
  echo "}" >> $OUTFILE
}

_install_grav () {
  if [[ -d "/home/grav/www/html" ]]; then
    cd /home/grav/www/html
    unzip /grav-admin-v1.3.0-rc.5.zip
    rsync -vua --delete-after grav-admin/ .
  else
    mkdir -p /home/grav/www
    cd /home/grav/www
    unzip /grav-admin-v1.3.0-rc.5.zip
    mv grav-admin html
  fi
  chown -R grav:grav /home/grav
}

_self_gen_ssl_cert () {
  if [[ ! -e local.dev.crt || ! -e local.dev.key ]]; then
    openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
      -subj "/C=US/ST=North Carolina/L=Chapel Hill/O=Local/OU=Development/CN=local.dev/emailAddress=email@local.dev" \
      -keyout local.dev.key \
      -out local.dev.crt
  fi
  cp local.dev.crt ${SSL_CERTIFICATE}
  cp local.dev.key ${SSL_CERTIFICATE_KEY}
}

if [[ "$1" = 'grav' ]]; then
  # update UID and GID values
  _update_uid_gid
  # update mime.types
  _mime_types
  # start Nginx and php7.0-fpm
  /etc/init.d/nginx start
  /etc/init.d/php7.0-fpm start
  # set: cgi.fix_pathinfo=0 in /etc/php/7.0/fpm/php.ini
  sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php/7.0/fpm/php.ini
  # Fix against httpoxy vulnerability
  echo "fastcgi_param  HTTP_PROXY         \"\";" >> /etc/nginx/fastcgi.conf
  # set /etc/nginx/nginx.conf
  _nginx_conf
  # set /etc/php/7.0/fpm/pool.d/grav.conf
  _grav_conf
  # install grav
  if ! [ "$(ls -A /home/grav/www/html)" ]; then
    _install_grav
  fi
  # based on SSL configuration
  # set /etc/nginx/sites-available/grav and /etc/nginx/sites-enabled/grav
  if $USE_SSL; then
    _https_grav_site
    _ssl_conf
    if $USE_SELF_GEN_CERT; then
      _self_gen_ssl_cert
    fi
  else
    _http_grav_site
  fi
  # restart Nginx and php7.0-fpm
  /etc/init.d/nginx restart
  /etc/init.d/php7.0-fpm restart
  rm -f /etc/nginx/sites-available/defalt
  rm -f /etc/nginx/sites-enabled/default
  /etc/init.d/nginx reload
  # Keep container alive
  tail -f /dev/null
else
    exec "$@"
fi

exit 0;
