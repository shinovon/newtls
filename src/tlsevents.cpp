#include "tlsevents.h"
#include "mbedcontext.h"
#include "LOGFILE.h"
#include "tlsconnection.h"
#include "es_sock.h"

LOCAL_C int send_callback(void *ctx, const unsigned char *buf, size_t len)
{
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
	CRecvEvent* s = (CRecvEvent*) ctx;
	
	TPtr8 des = TPtr8(buf, len);
	
	if (s->iReadState == 0 || s->iReadState == 2) {
		TRequestStatus stat;
		s->iSocket.Recv(des, 0, stat);
		User::WaitForRequest(stat);
		
		TInt ret = stat.Int() != KErrNone ? stat.Int() : des.Length();
		if (ret == KErrEof) ret = 0;
		return ret;
	}
	
	des.Copy(s->iPtrHBuf);
	s->iReadState = 2;
	return len;
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
	Resume(aTlsConnection);
}

void CRecvData::Suspend()
{
	LOG(Log::Printf(_L("CRecvData::Suspend()")));
	iRecvEvent.SetData(NULL);
}

void CRecvData::Resume(CTlsConnection& aTlsConnection)
{
	iRecvEvent.Set(this);
	if (!iActiveEvent) {
		iActiveEvent = &iRecvEvent;
	}
}

void CRecvData::OnCompletion()
{
	LOG(Log::Printf(_L("CRecvData::OnCompletion()")));
	if (iLastError == KErrNone && iStatus.Int() == KErrNone) {
		TDes8* pData = iRecvEvent.Data();
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
	
	iRecvEvent.SetData(NULL);
	
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
  iReadState(0)
{
	aMbedContext.SetBio(this, (TAny*) send_callback, (TAny*) recv_callback, NULL);
}

CRecvEvent::~CRecvEvent()
{
	LOG(Log::Printf(_L("CRecvEvent::~CRecvEvent()")));
	delete iDataIn;
}

void CRecvEvent::CancelAll()
{
	
}

void CRecvEvent::Set(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
	if (!iDataIn) {
		iDataIn = HBufC8::NewL(8);
	}
	iReadState = 0;
	iCurrentPos = 0;
}

CAsynchEvent* CRecvEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CRecvEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	
	TInt ret = KErrNone;
	switch (iReadState) {
	case 0: // read tls header
	{
		iPtrHBuf.Set((TUint8*)iDataIn->Des().Ptr(), 0, 5);
		TSockXfrLength len;
		iSocket.Recv(iPtrHBuf, 0, aStatus);
		iReadState = 1;
		return this;
	}
	case 1: // read data
	{
		if (iStateMachine->LastError() != KErrNone) {
			User::RequestComplete(pStatus, ret);
			return NULL;
		}
		TInt res = iMbedContext.Read((unsigned char*) iData->Ptr() + iCurrentPos, iData->MaxLength() - iCurrentPos);
		if (res == 0 || res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			ret = KErrEof;
			LOG(Log::Printf(_L("CRecvEvent::ProcessL() Eof")));
			break;
		}
		if (res == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
			iReadState = 3;
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		if (res < 0) {
			ret = res;
			LOG(Log::Printf(_L("CRecvEvent::ProcessL() Err: %x"), -res));
			break;
		}

		iData->SetLength(iCurrentPos + res);
		iCurrentPos += res;
	}
	break;
	case 3: // reconnect
	{
		TInt res = iMbedContext.Handshake();
		iReadState = 1;
		if (res == 0) {
			User::RequestComplete(pStatus, KErrNone);
			return this;
		}
		LOG(Log::Printf(_L("CRecvEvent::ProcessL() Handshake err: %x"), -res));
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
	Resume(aTlsConnection);
}

void CSendData::Suspend()
{
	LOG(Log::Printf(_L("CSendData::Suspend()")));
	iSendEvent.SetData(NULL);
	iSendEvent.SetSockXfrLength(NULL);
}

void CSendData::Resume(CTlsConnection& aTlsConnection)
{
	iSendEvent.Set(this);
	if (!iActiveEvent) {
		iActiveEvent = &iSendEvent;
	}
}

void CSendData::OnCompletion()
{
	LOG(Log::Printf(_L("CSendData::OnCompletion()")));
	
	iSendEvent.SetData(NULL);
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

void CSendEvent::CancelAll()
{
	
}

CAsynchEvent* CSendEvent::ProcessL(TRequestStatus& aStatus)
{
	TRequestStatus* pStatus = &aStatus;
	TInt ret = KErrNone;
	TInt res = iMbedContext.Write(iData->Ptr(), iData->Length());
	if (res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		res = KErrEof;
	} else if (res < 0) {
		// TODO reconnect support
		ret = res;
		LOG(Log::Printf(_L("CSendEvent::ProcessL() Err: %x"), -res));
	} else if (iSockXfrLength) {
		*iSockXfrLength = res;
	}
//	else if (res != iData->Length()) {
//		// TODO error
//	}
	
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
