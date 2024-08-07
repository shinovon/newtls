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

TInt CMbedContext::Handshake()
{
	return mbedtls_ssl_handshake(&ssl);
}

TInt CMbedContext::Read(TDes8& aDesc, TInt aLen)
{
	// TODO ??
	return mbedtls_ssl_read(&ssl, (unsigned char*) aDesc.Ptr(), (int) aLen);
}

TInt CMbedContext::Write(const TDesC8& aDesc, TInt aLen)
{
	return mbedtls_ssl_write(&ssl, (const unsigned char*) aDesc.Ptr(), (int) aLen);
}

TInt CMbedContext::SslCloseNotify()
{
	return mbedtls_ssl_close_notify(&ssl);
}
