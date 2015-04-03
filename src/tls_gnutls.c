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

/*! \file tls_gnutls.c
 * \brief Includes all GNUTLS-specific TLS functions
 * \version $Id$
 */

#include "stdinc.h"
#include "tls.h"
#include "conf.h"
#include "log.h"
#include "rsa.h"
#include "memory.h"

#ifdef HAVE_TLS_GNUTLS

/* tls_init()
 *
 * inputs       - nothing
 * output       - nothing
 * side effects - setups SSL context.
 */
void
tls_init(void)
{
  int ret;

  ret = gnutls_certificate_allocate_credentials(&ConfigServerInfo.tls_ctx.x509_cred);
  if (ret < 0)
  {
    const char *error = gnutls_strerror(ret);

    fprintf(stderr, "ERROR: Could not initialize the SSL credentials -- %s\n", error);
    ilog(LOG_TYPE_IRCD, "ERROR: Could not initialize the SSL credentials -- %s", error);
    exit(EXIT_FAILURE);
  }

  gnutls_dh_params_t dh_params;
  ret = gnutls_dh_params_init(&dh_params);
  // XXX load dhparams from file?

  gnutls_priority_init(&ConfigServerInfo.tls_ctx.priorities, "NORMAL", NULL);
}

int
tls_new_cred()
{
  int ret;

  ret = gnutls_certificate_set_x509_key_file(ConfigServerInfo.tls_ctx.x509_cred, ConfigServerInfo.ssl_certificate_file, ConfigServerInfo.rsa_private_key_file, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
  {
  }

  return 1;
}

inline static const char *
UnknownIfNULL(const char* str)
{
  return str ? str : "UNKNOWN";
}

const char *
tls_get_cipher(const tls_data_t *tls_data)
{
  static char buffer[IRCD_BUFSIZE];

  snprintf(buffer, sizeof(buffer), "%s-%s-%s",
           UnknownIfNULL(gnutls_kx_get_name(gnutls_kx_get(*tls_data))),
           UnknownIfNULL(gnutls_cipher_get_name(gnutls_cipher_get(*tls_data))),
           UnknownIfNULL(gnutls_mac_get_name(gnutls_mac_get(*tls_data))));

  return buffer;
}

int
tls_isusing(tls_data_t *tls_data)
{
  return *tls_data != NULL;
}

void
tls_free(tls_data_t *tls_data)
{
  gnutls_deinit(*tls_data);
}

int
tls_read(tls_data_t *tls_data, char *buf, size_t bufsize, int *want_write)
{
  int length = gnutls_record_recv(*tls_data, buf, bufsize);

  if (length <= 0)
  {
    switch (length)
    {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
        errno = EWOULDBLOCK;
        return -1;
      case 0: // closed
      default: // other error
        return -1;
    }
  }

  return length;
}

int
tls_write(tls_data_t *tls_data, const char *buf, size_t bufsize, int *want_read)
{
  int length = gnutls_record_send(*tls_data, buf, bufsize);

  if (length <= 0)
  {
    switch (length)
    {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
      case 0:
        errno = EWOULDBLOCK;
        return 0;
      default:
        return -1;
    }
  }

  return length;
}

void
tls_shutdown(tls_data_t *tls_data)
{
  gnutls_bye(*tls_data, GNUTLS_SHUT_WR);
}

int
tls_new(tls_data_t *tls_data, int fd, tls_role_t role)
{
  gnutls_init(tls_data, role == TLS_ROLE_SERVER ? GNUTLS_SERVER : GNUTLS_CLIENT);

  gnutls_priority_set(*tls_data, ConfigServerInfo.tls_ctx.priorities);
  gnutls_credentials_set(*tls_data, GNUTLS_CRD_CERTIFICATE, ConfigServerInfo.tls_ctx.x509_cred);
  //gnutls_dh_set_prime_bits(session->sess, dh_bits);
  //gnutls_transport_set_ptr(session->sess, reinterpret_cast<gnutls_transport_ptr_t>(session));
  //gnutls_transport_set_push_function(session->sess, gnutls_push_wrapper);
  //gnutls_transport_set_pull_function(session->sess, gnutls_pull_wrapper);

  if (role == TLS_ROLE_SERVER)
    gnutls_certificate_server_set_request(*tls_data, GNUTLS_CERT_REQUEST); // Request client certificate if any.

  return 1;
}

int
tls_set_ciphers(tls_data_t *tls_data, const char *cipher_list)
{
  int ret;
  const char *prioerror;

  ret = gnutls_priority_init(&ConfigServerInfo.tls_ctx.priorities, cipher_list, &prioerror);
  if (ret < 0)
  {
    // gnutls did not understand the user supplied string, log and fall back to the default priorities
    ilog(LOG_TYPE_IRCD, "Failed to set gnutls priorities to \"%s\": %s Syntax error at position %u, falling back to default (NORMAL)", cipher_list, gnutls_strerror(ret), (unsigned int) (prioerror - cipher_list));
    gnutls_priority_init(&ConfigServerInfo.tls_ctx.priorities, "NORMAL", NULL);
    return 0;
  }

  return 1;
}

tls_handshake_status_t
tls_handshake(tls_data_t *tls_data, tls_role_t role, const char **errstr)
{
  int ret = gnutls_handshake(*tls_data);

  if (ret >= 0)
    return TLS_HANDSHAKE_DONE;

  if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
  {
    // Handshake needs resuming later, read() or write() would have blocked.

    if (gnutls_record_get_direction(*tls_data) == 0)
    {
      // gnutls_handshake() wants to read() again.
      return TLS_HANDSHAKE_WANT_READ;
    }
    else
    {
      // gnutls_handshake() wants to write() again.
      return TLS_HANDSHAKE_WANT_WRITE;
    }
  }
  else
  {
    const char *error = gnutls_strerror(ret);

    if (errstr)
      *errstr = error;

    return TLS_HANDSHAKE_ERROR;
  }
}

int
tls_verify_cert(tls_data_t *tls_data, tls_md_t digest, char **fingerprint, int *raw_result)
{
  int ret;
  gnutls_x509_crt_t cert;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  unsigned char digestbuf[IRCD_BUFSIZE];
  size_t digest_size = sizeof(digestbuf);
  char buf[IRCD_BUFSIZE];

  cert_list_size = 0;
  cert_list = gnutls_certificate_get_peers(*tls_data, &cert_list_size);
  if (cert_list == NULL)
  {
    /* no certificate */
    return 1;
  }

  ret = gnutls_x509_crt_init(&cert);
  if (ret < 0)
  {
    return 1;
  }

  ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
  if (ret < 0)
  {
    goto info_done_dealloc;
  }

  ret = gnutls_x509_crt_get_fingerprint(cert, digest, digestbuf, &digest_size);
  if (ret < 0)
  {
    goto info_done_dealloc;
  }

  binary_to_hex(digestbuf, buf, digest_size);
  *fingerprint = xstrdup(buf);

  return 1;

 info_done_dealloc:
  gnutls_x509_crt_deinit(cert);
  return 0;
}

#endif /* HAVE_TLS_GNUTLS */
