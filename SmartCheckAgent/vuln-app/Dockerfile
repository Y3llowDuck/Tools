# Deliberately-vulnerable test target for CVE-2026-109618 / CVE-2026-109619.
#
# PHP 8.3.0 is < the patched 8.3.36, so version-based detection should flag it.
# This image is for LOCAL detection testing only. Do not expose it to a network.
FROM php:8.3.0-apache

# Keep expose_php=On so PHP emits "X-Powered-By: PHP/8.3.0" — the banner that
# version-based CVE detection fingerprints. (This is PHP's default; set it
# explicitly so the target stays deterministic even if the base image changes.)
RUN printf "expose_php = On\n" > /usr/local/etc/php/conf.d/zz-expose-php.ini

# Surface the PHP version in the Apache Server header too, for scanners that
# fingerprint on Server: rather than X-Powered-By:.
RUN { \
      echo "ServerTokens Full"; \
      echo "ServerSignature On"; \
    } > /etc/apache2/conf-available/zz-vuln-banner.conf \
 && a2enconf zz-vuln-banner

COPY src/ /var/www/html/

EXPOSE 80
