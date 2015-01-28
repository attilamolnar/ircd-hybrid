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

static int
always_accept_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
  return 1;
}

/* tls_init()
 *
 * inputs       - nothing
 * output       - nothing
 * side effects - setups SSL context.
 */
void
tls_init(void)
{
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  if (!(ConfigServerInfo.server_ctx = SSL_CTX_new(SSLv23_server_method())))
  {
    const char *s = ERR_lib_error_string(ERR_get_error());

    fprintf(stderr, "ERROR: Could not initialize the SSL Server context -- %s\n", s);
    ilog(LOG_TYPE_IRCD, "ERROR: Could not initialize the SSL Server context -- %s", s);
    exit(EXIT_FAILURE);
    return;  /* Not reached */
  }

  SSL_CTX_set_options(ConfigServerInfo.server_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TICKET);
  SSL_CTX_set_options(ConfigServerInfo.server_ctx, SSL_OP_SINGLE_DH_USE|SSL_OP_CIPHER_SERVER_PREFERENCE);
  SSL_CTX_set_verify(ConfigServerInfo.server_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,
                     always_accept_verify_cb);
  SSL_CTX_set_session_cache_mode(ConfigServerInfo.server_ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_cipher_list(ConfigServerInfo.server_ctx, "EECDH+HIGH:EDH+HIGH:HIGH:!aNULL");

#if OPENSSL_VERSION_NUMBER >= 0x009080FFL && !defined(OPENSSL_NO_ECDH)
  {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if (key)
    {
      SSL_CTX_set_tmp_ecdh(ConfigServerInfo.server_ctx, key);
      EC_KEY_free(key);
    }
  }

  SSL_CTX_set_options(ConfigServerInfo.server_ctx, SSL_OP_SINGLE_ECDH_USE);
#endif

  if (!(ConfigServerInfo.client_ctx = SSL_CTX_new(SSLv23_client_method())))
  {
    const char *s = ERR_lib_error_string(ERR_get_error());

    fprintf(stderr, "ERROR: Could not initialize the SSL Client context -- %s\n", s);
    ilog(LOG_TYPE_IRCD, "ERROR: Could not initialize the SSL Client context -- %s", s);
    exit(EXIT_FAILURE);
    return;  /* Not reached */
  }

  SSL_CTX_set_options(ConfigServerInfo.client_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TICKET);
  SSL_CTX_set_options(ConfigServerInfo.client_ctx, SSL_OP_SINGLE_DH_USE);
  SSL_CTX_set_verify(ConfigServerInfo.client_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,
                     always_accept_verify_cb);
  SSL_CTX_set_session_cache_mode(ConfigServerInfo.client_ctx, SSL_SESS_CACHE_OFF);
}

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

int
tls_isusing(tls_data_t *tls_data)
{
  SSL *ssl = *tls_data;
  return (ssl != NULL);
}

void
tls_free(tls_data_t *tls_data)
{
  SSL_free(*tls_data);
  *tls_data = NULL;
}

int
tls_read(tls_data_t *tls_data, char *buf, size_t bufsize, int *want_write)
{
  SSL *ssl = *tls_data;
  int length = SSL_read(ssl, buf, bufsize);

  /* translate openssl error codes, sigh */
  if (length < 0)
  {
	switch (SSL_get_error(ssl, length))
	{
	  case SSL_ERROR_WANT_WRITE:
	  {
		/* OpenSSL wants to write, we signal this to the caller and do nothing about that here */
	    *want_write = 1;
		break;
	  }
	  case SSL_ERROR_WANT_READ:
		  errno = EWOULDBLOCK;
	  case SSL_ERROR_SYSCALL:
		  break;
	  case SSL_ERROR_SSL:
		if (errno == EAGAIN)
		  break;
		/* fall through */
	  default:
		length = errno = 0;
	}
  }
  return length;
}

int
tls_write(tls_data_t *tls_data, const char *buf, size_t bufsize, int *want_read)
{
  SSL *ssl = *tls_data;
  int retlen = SSL_write(ssl, buf, bufsize);

  /* translate openssl error codes, sigh */
  if (retlen < 0)
  {
    switch (SSL_get_error(ssl, retlen))
    {
	  case SSL_ERROR_WANT_READ:
	  	*want_read = 1;
	    break;  /* retry later, don't register for write events */
	  case SSL_ERROR_WANT_WRITE:
		errno = EWOULDBLOCK;
	  case SSL_ERROR_SYSCALL:
	    break;
	  case SSL_ERROR_SSL:
	    if (errno == EAGAIN)
		  break;
		/* fall through */
	  default:
	    retlen = errno = 0;  /* either an SSL-specific error or EOF */
    }
  }
  return retlen;
}

void
tls_shutdown(tls_data_t *tls_data)
{
  SSL *ssl = *tls_data;

  SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
  if (!SSL_shutdown(ssl))
    SSL_shutdown(ssl);
}

int
tls_new(tls_data_t *tls_data, int fd, tls_role_t role)
{
  SSL *ssl;
  if (role == TLS_ROLE_SERVER)
    ssl = SSL_new(ConfigServerInfo.server_ctx);
  else
    ssl = SSL_new(ConfigServerInfo.client_ctx);

  if (!ssl)
  {
      ilog(LOG_TYPE_IRCD, "SSL_new() ERROR! -- %s",
           ERR_error_string(ERR_get_error(), NULL));
      return 0;
  }

  *tls_data = ssl;
  SSL_set_fd(ssl, fd);
  return 1;
}

int
tls_set_ciphers(tls_data_t *tls_data, const char *cipher_list)
{
  SSL_set_cipher_list(*tls_data, cipher_list);
  return 1;
}
