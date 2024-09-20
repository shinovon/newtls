/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 */

#include "mbedcontext.h"

CMbedContext::CMbedContext()
{
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
}

CMbedContext::~CMbedContext()
{
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

void CMbedContext::SetBio(TAny* aContext, TAny* aSend, TAny* aRecv, TAny* aTimeout)
{
	mbedtls_ssl_set_bio(&ssl,
		aContext,
		(mbedtls_ssl_send_t *) aSend,
		(mbedtls_ssl_recv_t *) aRecv,
		(mbedtls_ssl_recv_timeout_t *) aTimeout);
}

TInt CMbedContext::InitSsl()
{
	TInt ret(0);
	
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									 NULL, 0)) != 0) {
		goto exit;
	}

	if ((ret = mbedtls_ssl_config_defaults(&conf,
											   MBEDTLS_SSL_IS_CLIENT,
											   MBEDTLS_SSL_TRANSPORT_STREAM,
											   MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		goto exit;
	}
	
	
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_session_tickets(&conf, 0);
	mbedtls_ssl_conf_renegotiation(&conf, 0);
	
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		goto exit;
	}
	
	exit:
	return ret;
}

void CMbedContext::SetHostname(const char* aHostname)
{
	mbedtls_ssl_set_hostname(&ssl, aHostname);
}

TInt CMbedContext::Handshake()
{
	int ret;
	
	do {
		ret = mbedtls_ssl_handshake(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
		ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
		ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS);
	
	return ret;
}

//TInt CMbedContext::Renegotiate()
//{
//	return mbedtls_ssl_renegotiate(&ssl);
//}

//TInt CMbedContext::ExportSession(unsigned char *aData, TInt aMaxLen, TUint* aLen) {
//    mbedtls_ssl_session exported_session;
//    mbedtls_ssl_session_init(&exported_session);
//    int ret = mbedtls_ssl_get_session(ssl, &exported_session);
//    if (ret != 0) goto exit;
//	ret = mbedtls_ssl_session_save(&exported_session, aData, static_cast<unsigned int>(aMaxLen), aLen);
//exit:
//	mbedtls_ssl_session_free(&exported_session);
//	return ret;
//}

//TInt CMbedContext::LoadSession(const unsigned char *aData, TInt aLen) {
//	return -1;
//}

TInt CMbedContext::Read(unsigned char* aData, TInt aLen)
{
	int ret;
	do {
		ret = mbedtls_ssl_read(&ssl, aData, static_cast<unsigned int>(aLen));
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS);
	return ret;
}

TInt CMbedContext::Write(const unsigned char* aData, TInt aLen)
{
	int ret;
	do {
		ret = mbedtls_ssl_write(&ssl, aData, static_cast<unsigned int>(aLen));
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS);
	return ret;
}

TInt CMbedContext::SslCloseNotify()
{
	int ret;
	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	return ret;
}

TInt CMbedContext::Reset() {
	return mbedtls_ssl_session_reset(&ssl);
}
