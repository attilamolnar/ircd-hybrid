/*
 *  ircd-hybrid: an advanced, lightweight Internet Relay Chat Daemon (ircd)
 *
 *  Copyright (c) 1997-2015 ircd-hybrid development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 *  USA
 */

/*! \file tls_openssl.c
 * \brief Includes all OpenSSL-specific TLS functions
 * \version $Id$
 */

const char *
tls_get_cipher(const tls_data_t *tls_data)
{
  static char buffer[IRCD_BUFSIZE];
  int bits = 0;
  SSL *ssl = *tls_data;

  SSL_CIPHER_get_bits(SSL_get_current_cipher(ssl), &bits);

  snprintf(buffer, sizeof(buffer), "%s-%s-%d", SSL_get_version(ssl),
           SSL_get_cipher(ssl), bits);
  return buffer;
}
