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
	
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		goto exit;
	}
	
	exit:
	return ret;
}

TInt CMbedContext::Handshake()
{
	int ret(0);
	
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
			continue;
		}
			
		break;
	}
	
	return ret;
}

//TInt CMbedContext::Renegotiate()
//{
//	return mbedtls_ssl_renegotiate(&ssl);
//}

TInt CMbedContext::Read(unsigned char* aData, TInt aLen)
{
	int r;
	do {
		r = mbedtls_ssl_read(&ssl, aData, static_cast<unsigned int>(aLen));
		
		if (r == MBEDTLS_ERR_SSL_WANT_READ ||
			r == MBEDTLS_ERR_SSL_WANT_WRITE ||
			r == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			r == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
			continue;
		}
		if (r < 0) {
			break;
		}
		break;
	} while (1);
	return r;
	
//	return mbedtls_ssl_read(&ssl, aData, static_cast<unsigned int>(aLen));
}

TInt CMbedContext::Write(const unsigned char* aData, TInt aLen)
{
	int r;
	do {
		r = mbedtls_ssl_write(&ssl, aData, static_cast<unsigned int>(aLen));
		if (r == MBEDTLS_ERR_SSL_WANT_READ ||
			r == MBEDTLS_ERR_SSL_WANT_WRITE ||
			r == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			r == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
			continue;
		}
		if (r < 0) {
			break;
		}
		break;
	} while(1);
	return r;
}

TInt CMbedContext::SslCloseNotify()
{
	return mbedtls_ssl_close_notify(&ssl);
}
