/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 * Copyright (c) 2009 Nokia Corporation
 */

#include "tlsevents.h"
#include "mbedcontext.h"
#include "LOGFILE.h"
#include "tlsconnection.h"
#include "es_sock.h"

// callbacks for mbedtls

LOCAL_C int send_callback(void *ctx, const unsigned char *buf, size_t len)
{
	LOG(Log::Printf(_L("+send_callback %d"), len));
	CBio* s = (CBio*) ctx;
	
	if (s->iWriteState == 1 && s->iWriteLength == len) {
		s->iWriteState = 0;
		return len;
	}
	
	if (s->iWriteState == 0) {
		s->iWritePtr = (const TUint8*) buf;
		s->iWriteLength = len;
		s->iWriteState = 2;
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	
	const TPtrC8 des((const TUint8*) buf, len);
	
	TRequestStatus stat;
	s->iSocket.Send(des, 0, stat);
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : len;
	return ret;
}

LOCAL_C int recv_callback(void *ctx, unsigned char *buf, size_t len)
{
	LOG(Log::Printf(_L("+recv_callback %d"), len));
	CBio* s = (CBio*) ctx;
	
	TPtr8 des = TPtr8(buf, 0, len);
	
	if (s->iReadState == 1) {
		// TODO check for overflow
		if (s->iPtrHBuf.Length() > len) {
			User::Panic(_L("newtls"), 1);
			return 0;
		}
		des.Copy(s->iPtrHBuf);
		s->iReadState = 0;
		return s->iPtrHBuf.Length();
	}
	
	if (s->iReadState == 0) {
		s->iReadLength = len;
		s->iReadState = 2;
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	
	s->iReadLength = 0;
	
	TRequestStatus stat;
	s->iSocket.Recv(des, 0, stat);
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : des.Length();
	if (ret == KErrEof) ret = 0;
	LOG(Log::Printf(_L("-recv_callback %d (%d)"), ret, stat.Int()));
	return ret;
}

//

CBio* CBio::NewL(CTlsConnection& aTlsConnection)
{
	CBio* self = new(ELeave) CBio(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL(aTlsConnection);
	CleanupStack::Pop();
	return self;
}

CBio::CBio(CTlsConnection& aTlsConnection) :
  iSocket(aTlsConnection.Socket()),
  iPtrHBuf(0, 0),
  iReadState(0),
  iWriteState(0)
{
	aTlsConnection.MbedContext().SetBio(this, (TAny*) send_callback, (TAny*) recv_callback, NULL);
}

void CBio::ConstructL(CTlsConnection& aTlsConnection)
{
	if (!iDataIn) {
		iDataIn = HBufC8::NewL(0x1000);
	}
}

CBio::~CBio()
{
	delete iDataIn;
}

void CBio::Recv(TRequestStatus*& aStatus)
{
	LOG(Log::Printf(_L("Receive data")));
	if (iReadState == 1) {
		User::RequestComplete(aStatus, KErrNone);
		return;
	}
	if (iReadLength > iDataIn->Length()) {
		delete iDataIn;
		iDataIn = NULL;
		iDataIn = HBufC8::NewL(iReadLength);
	}
	iPtrHBuf.Set((TUint8*)iDataIn->Des().Ptr(), 0, iReadLength ? iReadLength : 5);
	TSockXfrLength len;
	iSocket.Recv(iPtrHBuf, 0, *aStatus);
	iReadState = 1;
	iReadLength = 0;
}

void CBio::Send(TRequestStatus*& aStatus)
{
	if (iWriteState == 1 || !iWritePtr) {
		// should not happen
		User::RequestComplete(aStatus, KErrNone);
		return;
	}
	const TPtrC8 des((const TUint8*) iWritePtr, iWriteLength);
	
	iSocket.Send(des, 0, *aStatus);
	iWriteState = 1;
	iWritePtr = NULL;
}

void CBio::ClearRecvBuffer()
{
	iReadState = 0;
}

void CBio::ClearSendBuffer()
{
	iWritePtr = NULL;
	iWriteState = 0;
}

// recvdata

CRecvData* CRecvData::NewL(CTlsConnection& aTlsConnection)
{
	CRecvData* self = new(ELeave) CRecvData(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL(aTlsConnection);
	CleanupStack::Pop();
	return self;
}

CRecvData::CRecvData(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
  iRecvEvent(aTlsConnection.RecvEvent())
{
	
}

CRecvData::~CRecvData()
{
	LOG(Log::Printf(_L("CRecvData::~CRecvData")));
	SetSockXfrLength(NULL);
	Cancel(KErrNone);
}

void CRecvData::ConstructL(CTlsConnection& aTlsConnection)
{
	LOG(Log::Printf(_L("CRecvData::ConstructL()")));
	Resume();
}

void CRecvData::Suspend()
{
	LOG(Log::Printf(_L("CRecvData::Suspend()")));
	iUserData = iRecvEvent.UserData();
	iRecvEvent.SetUserData(NULL);
}

void CRecvData::Resume()
{
	iRecvEvent.SetUserData(iUserData);
	iRecvEvent.SetUserMaxLength(iUserData ? iUserData->MaxLength() : 0);
	iRecvEvent.ReConstruct(this);
	
	if (!iActiveEvent) {
		iActiveEvent = &iRecvEvent;
	}
}

void CRecvData::OnCompletion()
{
	LOG(Log::Printf(_L("CRecvData::OnCompletion()")));
	if (iLastError == KErrNone && iStatus.Int() == KErrNone) {
		TDes8* pData = iRecvEvent.UserData();
		if (pData) {
			if (iSockXfrLength && pData->Length()) {
				*iSockXfrLength = pData->Length();
			}
			else if (pData->Length() < pData->MaxLength()) {
				iActiveEvent = &iRecvEvent;
				Start(iClientStatus, iStateMachineNotify);
				return;
			}
		}
	}
	
	iRecvEvent.SetUserData(NULL);
	iRecvEvent.SetUserMaxLength(0);
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete(p, iLastError);
	}
	
	CStateMachine::OnCompletion();
}

void CRecvData::DoCancel()
{
	LOG(Log::Printf(_L("CRecvData::DoCancel()")));
	iLastError = KErrCancel;
	iRecvEvent.CancelAll();
	CStateMachine::DoCancel();
}

// recvevent

CRecvEvent::CRecvEvent(CMbedContext& aMbedContext, CBio& aBio) :
  CAsynchEvent(0),
  iMbedContext(aMbedContext),
  iBio(aBio)
{
}

CRecvEvent::~CRecvEvent()
{
	LOG(Log::Printf(_L("CRecvEvent::~CRecvEvent()")));
}

void CRecvEvent::CancelAll()
{
	iBio.ClearRecvBuffer();
}

void CRecvEvent::ReConstruct(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
}

CAsynchEvent* CRecvEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CRecvEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	
	TInt ret = KErrNone;
	if (iStateMachine->LastError() != KErrNone) {
		User::RequestComplete(pStatus, iStateMachine->LastError());
		return NULL;
	}
	TInt offset = iUserData->Length();
	TInt res = iMbedContext.Read((unsigned char*) iUserData->Ptr() + offset, iUserMaxLength - offset);
	if (res == MBEDTLS_ERR_SSL_WANT_READ) {
		iBio.Recv(pStatus);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
		iBio.Send(pStatus);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
		LOG(Log::Printf(_L("Ticket received on read")));
		User::RequestComplete(pStatus, KErrNone);
		return this;
	}
	if (res == 0 || res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		ret = KErrEof;
		LOG(Log::Printf(_L("Read eof")));
	} else if (res < 0) {
		ret = res;
		LOG(Log::Printf(_L("Read error: %x"), -res));
	}
//		LOG(Log::Printf(_L("Recv %d"), res));

	if (offset + res > iUserData->MaxLength()) {
		User::Panic(_L("newtls"), 2);
	}
	iUserData->SetLength(offset + res);
	
	User::RequestComplete(pStatus, ret);
	return NULL;
}

// senddata

CSendData* CSendData::NewL(CTlsConnection& aTlsConnection)
{
	CSendData* self = new(ELeave) CSendData(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL(aTlsConnection);
	CleanupStack::Pop();
	return self;
}

CSendData::CSendData(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
  iSendEvent(aTlsConnection.SendEvent())
{
	
}

CSendData::~CSendData()
{
	LOG(Log::Printf(_L("CSendData::~CSendData")));
	Cancel(KErrNone);
}

void CSendData::ConstructL(CTlsConnection& aTlsConnection)
{
	LOG(Log::Printf(_L("CSendData::ConstructL()")));
	Resume();
}

void CSendData::Suspend()
{
	LOG(Log::Printf(_L("CSendData::Suspend()")));
	iCurrentPos = iSendEvent.CurrentPos();
	iSendEvent.SetUserData(NULL);
}

void CSendData::Resume()
{
	iSendEvent.SetUserData(iUserData);
	iSendEvent.ReConstruct(this, iCurrentPos);
	iCurrentPos = 0;
	
	if (!iActiveEvent) {
		iActiveEvent = &iSendEvent;
	}
}

void CSendData::SetSockXfrLength(TInt* aLen)
{
	iSockXfrLength = aLen;
	if (iSockXfrLength) {
		*iSockXfrLength = 0;
	}
}

void CSendData::OnCompletion()
{
	LOG(Log::Printf(_L("CSendData::OnCompletion()")));
	
	TDesC8* pAppData = iSendEvent.UserData();
	if (pAppData) {
		if (iSockXfrLength) {
			*iSockXfrLength = iSendEvent.CurrentPos();
		}
		if (iLastError == KErrNone && iStatus.Int() == KErrNone) {
			if (pAppData->Length() > iSendEvent.CurrentPos()) {
				iActiveEvent = &iSendEvent;
				Start(iClientStatus, iStateMachineNotify);
				return;
			}
		}
	}
	
	iSendEvent.SetUserData(NULL);
	iSendEvent.ResetCurrentPos();
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete(p, iLastError);
	}
	
	CStateMachine::OnCompletion();
}

void CSendData::DoCancel()
{
	LOG(Log::Printf(_L("CSendData::DoCancel()")));
	iLastError = KErrCancel;
	iSendEvent.CancelAll();
	CStateMachine::DoCancel();
}

// sendevent

CSendEvent::CSendEvent(CMbedContext& aMbedContext, CBio& aBio) :
  CAsynchEvent(0),
  iMbedContext(aMbedContext),
  iBio(aBio)
{
}

CSendEvent::~CSendEvent()
{
	LOG(Log::Printf(_L("CSendData::~CSendEvent")));
}

void CSendEvent::ReConstruct(CStateMachine* aStateMachine, TInt aCurrentPos)
{
	iStateMachine = aStateMachine;
	iCurrentPos = aCurrentPos;
}

void CSendEvent::CancelAll()
{
	iBio.ClearSendBuffer();
}

CAsynchEvent* CSendEvent::ProcessL(TRequestStatus& aStatus)
{
	TRequestStatus* pStatus = &aStatus;
	TInt ret = KErrNone;
	if (iStateMachine->LastError() != KErrNone) {
		User::RequestComplete(pStatus, iStateMachine->LastError());
		return NULL;
	}
	if (iData) {
		TInt res = iMbedContext.Write(iData->Ptr() + iCurrentPos, iData->Length() - iCurrentPos);
		if (res == MBEDTLS_ERR_SSL_WANT_READ) {
			iBio.Recv(pStatus);
			return this;
		}
		if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
			iBio.Send(pStatus);
			return this;
		}
		if (res == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			res == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS || 
			res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		if (res < 0) {
			if (res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				ret = KErrEof;
			}
			LOG(Log::Printf(_L("Write error: %x"), -res));
		} else {
			iCurrentPos += res;
		}
	}
	
	User::RequestComplete(pStatus, ret);
	return NULL;
}

// handshake

CHandshake* CHandshake::NewL(CTlsConnection& aTlsConnection)
{
	CHandshake* self = new(ELeave) CHandshake(aTlsConnection);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

CHandshake::CHandshake(CTlsConnection& aTlsConnection) :
  iTlsConnection(aTlsConnection),
  iHandshakeEvent(aTlsConnection.HandshakeEvent())
{
}

CHandshake::~CHandshake()
{
	LOG(Log::Printf(_L("CHandshake::~CHandshake()")));
	Cancel(KErrNone);
}

void CHandshake::ConstructL()
{
	LOG(Log::Printf(_L("CHandshake::CHandshake()")));
	Resume();
}

void CHandshake::Resume()
{
	iHandshakeEvent.Set(this);
	
	if (!iActiveEvent) {
		iActiveEvent = &iHandshakeEvent;
	}
}

void CHandshake::OnCompletion()
{
	LOG(Log::Printf(_L("CHandshake::OnCompletion()")));
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete(p, iLastError);
	}
	
	CStateMachine::OnCompletion();
}

void CHandshake::DoCancel()
{
	LOG(Log::Printf(_L("CHandshake::DoCancel()")));
	iLastError = KErrCancel;
	iHandshakeEvent.CancelAll();
	CStateMachine::DoCancel();
}

// handshake event

CHandshakeEvent::CHandshakeEvent(CMbedContext& aMbedContext, CBio& aBio) :
  CAsynchEvent(NULL),
  iMbedContext(aMbedContext),
  iBio(aBio)
{
}

CHandshakeEvent::~CHandshakeEvent()
{
	LOG(Log::Printf(_L("CHandshakeEvent::~CHandshakeEvent()")));
}

void CHandshakeEvent::CancelAll()
{
}

CAsynchEvent* CHandshakeEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CHandshakeEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	if (iStateMachine->LastError() != KErrNone) {
		User::RequestComplete(pStatus, iStateMachine->LastError());
		return NULL;
	}
	TInt res = iHandshaked ? iMbedContext.Renegotiate() : iMbedContext.Handshake();
	if (res == MBEDTLS_ERR_SSL_WANT_READ) {
		iBio.Recv(pStatus);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
		iBio.Send(pStatus);
		return this;
	}
	if (res == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
		res == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS || 
		res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
		User::RequestComplete(pStatus, KErrNone);
		return this;
	}
	TInt ret = KErrNone;
	if (res != 0) {
		ret = KErrSSLAlertHandshakeFailure;
		LOG(Log::Printf(_L("CHandshakeEvent::ProcessL() Err %x"), -res));
	}
	iHandshaked = ETrue;
	User::RequestComplete(pStatus, ret);
	return NULL;
}
