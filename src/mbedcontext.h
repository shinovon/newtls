#ifndef MBEDCONTEXT_H
#define MBEDCONTEXT_H
#include <e32base.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>

class CMbedContext : public CBase {
public:
	CMbedContext();
	~CMbedContext();
	
protected:
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

public:
	// mbedtls_ssl_set_bio
	void SetBio(TAny* aContext, TAny* aSend, TAny* aRecv, TAny* aTimeout);
	
	TInt InitSsl();
	
	// mbedtls_ssl_handshake
	TInt Handshake();
	
	// mbedtls_ssl_renegotiate
//	TInt Renegotiate();
	
	// mbedtls_ssl_read
	TInt Read(unsigned char* aData, TInt aLen);
	
	// mbedtls_ssl_write
	TInt Write(const unsigned char* aData, TInt aLen);
	
	// mbedtls_ssl_close_notify
	TInt SslCloseNotify();
};
#endif
