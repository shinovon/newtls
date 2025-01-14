/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 * Copyright (c) 2009 Nokia Corporation
 */

#include "tlsevents.h"
#include "mbedcontext.h"
#include "LOGFILE.h"
#include "tlsconnection.h"
#include "es_sock.h"

LOCAL_C int send_callback(void *ctx, const unsigned char *buf, size_t len)
{
	LOG(Log::Printf(_L("+send_callback %d"), len));
	CRecvEvent* s = (CRecvEvent*) ctx;
	
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
	CRecvEvent* s = (CRecvEvent*) ctx;
	
	TPtr8 des = TPtr8(buf, 0, len);
	
	if (s->iReadState == 1 && s->iBufferState) {
		des.Copy(s->iPtrHBuf);
		s->iBufferState = 0;
		s->iReadState = 2;
		return s->iPtrHBuf.MaxLength();
	}
	
	TRequestStatus stat;
	s->iSocket.Recv(des, 0, stat);
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : des.Length();
	if (ret == KErrEof) ret = 0;
	LOG(Log::Printf(_L("-recv_callback %d (%d)"), ret, stat.Int()));
	return ret;
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

CRecvEvent::CRecvEvent(CMbedContext& aMbedContext, MGenericSecureSocket& aSocket) :
  CAsynchEvent(0),
  iSocket(aSocket),
  iMbedContext(aMbedContext),
  iPtrHBuf(0, 0),
  iReadState(0),
  iBufferState(0)
{
	aMbedContext.SetBio(this, (TAny*) send_callback, (TAny*) recv_callback, NULL);
}

CRecvEvent::~CRecvEvent()
{
	LOG(Log::Printf(_L("CRecvEvent::~CRecvEvent()")));
	delete iHeaderData;
}

void CRecvEvent::CancelAll()
{
	iReadState = 0;
	iBufferState = 0;
}

void CRecvEvent::ReConstruct(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
	if (!iHeaderData) {
		iHeaderData = HBufC8::NewL(8);
	}
	iReadState = iBufferState == 1 ? 1 : 0;
}

CAsynchEvent* CRecvEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CRecvEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	
	TInt ret = KErrNone;
	switch (iReadState) {
	case 0: // read tls header
	{
		LOG(Log::Printf(_L("Read header")));
		iPtrHBuf.Set((TUint8*)iHeaderData->Des().Ptr(), 0, 5);
		TSockXfrLength len;
		iSocket.Recv(iPtrHBuf, 0, aStatus);
		iBufferState = 1;
		iReadState = 1;
		return this;
	}
	case 1: // read data
	case 2:
	{
		if (iStateMachine->LastError() != KErrNone) {
			User::RequestComplete(pStatus, ret);
			return NULL;
		}
		TInt offset = iUserData->Length();
		TInt res = iMbedContext.Read((unsigned char*) iUserData->Ptr() + offset, iUserMaxLength - offset);
		if (res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
			LOG(Log::Printf(_L("Ticket received on read")));
			if (!iBufferState) iReadState = 0;
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		if (res == 0 || res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			ret = KErrEof;
			LOG(Log::Printf(_L("Read eof")));
			break;
		}
		if (res == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
			LOG(Log::Printf(_L("Reconnect")));
			iReadState = 3;
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		if (res < 0) {
			ret = res;
			LOG(Log::Printf(_L("Read error: %x"), -res));
			break;
		}
//		LOG(Log::Printf(_L("Recv %d"), res));

		iUserData->SetLength(offset + res);
	}
	break;
	case 3: // reconnect
	{
		if (iBufferState) {
			LOG(Log::Printf(_L("Invalid buffer state on reconnect!")));
//			iBufferState = 0;
		}
		TInt res = iMbedContext.Handshake();
		iReadState = 0;
		if (res == 0) {
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		LOG(Log::Printf(_L("Reconnect handshake err: %x"), -res));
		// failed
		ret = res;
	}
	}
	
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
	iSendEvent.SetUserData(NULL);
	iSendEvent.SetSockXfrLength(NULL);
}

void CSendData::Resume()
{
	iSendEvent.ReConstruct(this);
	if (!iActiveEvent) {
		iActiveEvent = &iSendEvent;
	}
}

void CSendData::OnCompletion()
{
	LOG(Log::Printf(_L("CSendData::OnCompletion()")));
	
	iSendEvent.SetUserData(NULL);
	iSendEvent.SetSockXfrLength(NULL);
	
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

CSendEvent::CSendEvent(CMbedContext& aMbedContext) :
  CAsynchEvent(0),
  iMbedContext(aMbedContext)
{
}

CSendEvent::~CSendEvent()
{
	LOG(Log::Printf(_L("CSendData::~CSendEvent")));
	SetSockXfrLength(NULL);
}

void CSendEvent::ReConstruct(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
	iCurrentPos = 0;
}

void CSendEvent::CancelAll()
{
	
}

CAsynchEvent* CSendEvent::ProcessL(TRequestStatus& aStatus)
{
	TRequestStatus* pStatus = &aStatus;
	TInt ret = KErrNone;
	TInt res = iMbedContext.Write(iData->Ptr() + iCurrentPos, iData->Length() - iCurrentPos);
	if (res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
		LOG(Log::Printf(_L("Ticket received on write")));
		User::RequestComplete(pStatus, KErrNone);
		return this;
	}
	if (res < 0) {
		if (res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			ret = KErrEof;
		} else {
			// TODO reconnect?
			ret = res;
		}
		LOG(Log::Printf(_L("Write error: %x"), -res));
	} else if (iSockXfrLength) {
		*iSockXfrLength = res;
	} else {
		LOG(Log::Printf(_L("Write repeat")));
		iCurrentPos += res;
		if (iCurrentPos < iData->Length()) {
			User::RequestComplete(pStatus, KErrNone);
			return this;
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

CHandshakeEvent::CHandshakeEvent(CMbedContext& aMbedContext) :
  CAsynchEvent(NULL),
  iMbedContext(aMbedContext)
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
	TInt res = iMbedContext.Handshake();
	TInt ret = KErrNone;
	if (res != 0) {
		ret = KErrSSLAlertHandshakeFailure;
		LOG(Log::Printf(_L("CHandshakeEvent::ProcessL() Err %x"), -res));
	}
	User::RequestComplete(pStatus, ret);
	return NULL;
}
