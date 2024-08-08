#include "tlsevents.h"
#include "mbedcontext.h"
#include "LOGFILE.h"
#include "tlsconnection.h"
#include "es_sock.h"

LOCAL_C int send_callback(void *ctx, const unsigned char *buf, size_t len)
{
	LOG(Log::Printf(_L("+send_callback")));
	CRecvEvent* s = (CRecvEvent*) ctx;
	
	const TPtrC8 des((const TUint8*) buf, len);
	
	TRequestStatus stat;
	s->iSocket.Send(des, 0, stat);
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : len;
	LOG(Log::Printf(_L("-send_callback: %d"), ret));
	return ret;
}

LOCAL_C int recv_callback(void *ctx, unsigned char *buf, size_t len)
{
	LOG(Log::Printf(_L("+recv_callback")));
	CRecvEvent* s = (CRecvEvent*) ctx;
	
	TPtr8 des = TPtr8(buf, len);
	
//	if (s->iReadState == 0) {
	TRequestStatus stat;
	s->iSocket.RecvOneOrMore(des, 0, stat);
	LOG(Log::Printf(_L("recv_callback: wait")));
	User::WaitForRequest(stat);
	
	TInt ret = stat.Int() != KErrNone ? stat.Int() : des.Length();
	LOG(Log::Printf(_L("-recv_callback: %d"), ret));
	if (ret == KErrEof) ret = 0;
	return ret;
//	}
//	
//	TInt maxLen = s->iPtrHBuf.Length();
//	TInt readIdx = s->iReadIdx;
//	TInt resLen = len;
//	if (readIdx >= maxLen) {
//		LOG(Log::Printf(_L("-recv_callback fail 1")));
//		return -1;
//	}
//
//	const TUint8* ptr = s->iPtrHBuf.Ptr();
//	ptr += readIdx;
//	
//	if (resLen > maxLen-readIdx) {
//		resLen = maxLen-readIdx;
//	}
//	
//	s->iReadIdx += resLen;
//	
//	des.Copy(ptr, resLen);
//	LOG(Log::Printf(_L("-recv_callback g")));
//	return resLen;
}

CRecvData* CRecvData::NewL( CTlsConnection& aTlsConnection )
{
	CRecvData* self = new(ELeave) CRecvData( aTlsConnection );
	CleanupStack::PushL( self );
	self->ConstructL( aTlsConnection );
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
	SetSockXfrLength( NULL );
	Cancel( KErrNone );
}

void CRecvData::ConstructL( CTlsConnection& aTlsConnection )
{
	LOG(Log::Printf(_L("CRecvData::ConstructL()")));
	ResumeL(aTlsConnection);
}

void CRecvData::Suspend()
{
	LOG(Log::Printf(_L("CRecvData::Suspend()")));
	iRecvEvent.SetData( NULL );
	iRecvEvent.SetMaxLength( 0 );
}

void CRecvData::ResumeL( CTlsConnection& aTlsConnection )
{
	LOG(Log::Printf(_L("+CRecvData::ResumeL()")));
	if (!iActiveEvent) {
		iActiveEvent = &iRecvEvent;
	}
	LOG(Log::Printf(_L("-CRecvData::ResumeL()")));
}

void CRecvData::OnCompletion()
{
	LOG(Log::Printf(_L("CRecvData::OnCompletion()")));
	if (iLastError == KErrNone && iStatus.Int() == KErrNone) {
		TDes8* pData = iRecvEvent.Data();
		if (pData) {
			if (iSockXfrLength && pData->Length()) {
				*iSockXfrLength = pData->Length();
			} else if (pData->Length() < pData->MaxLength()) {
				iActiveEvent = &iRecvEvent;
				Start(iClientStatus, iStateMachineNotify);
				return;
			}
		}
	}
	
	iRecvEvent.SetData( NULL );
	iRecvEvent.SetMaxLength( 0 );
	
	iTlsConnection.DoneReading();
	
	if (iStatus.Int() == KRequestPending) {
		TRequestStatus* p = &iStatus;
		User::RequestComplete( p, iLastError );
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




CRecvEvent::CRecvEvent( CMbedContext& aMbedContext, CStateMachine* aStateMachine, RSocket& aSocket ) :
  CAsynchEvent(aStateMachine),
  iSocket(aSocket),
  iMbedContext(aMbedContext),
  iPtrHBuf( 0, 0 ),
  iReadIdx(0),
  iReadState(0)
{
	aMbedContext.SetBio(this, (TAny*) send_callback, (TAny*) recv_callback, NULL);
}

CRecvEvent::~CRecvEvent()
{
	LOG(Log::Printf(_L("CRecvEvent::~CRecvEvent()")));
}

void CRecvEvent::SetMaxLength(TInt aLen)
{
	
}

void CRecvEvent::CancelAll()
{
	
}

CAsynchEvent* CRecvEvent::ProcessL(TRequestStatus& aStatus)
{
	LOG(Log::Printf(_L("+CRecvEvent::ProcessL()")));
	TRequestStatus* pStatus = &aStatus;
	
//	if (!iDataIn) {
//		iDataIn = HBufC8::NewL( 4096 );
//	}
	TInt ret = KErrNone;
//	switch (iReadState) {
//	case 0:
//	{
//		LOG(Log::Printf(_L("ReadState 0")));
//		iPtrHBuf.Set( (TUint8*)iDataIn->Des().Ptr(), 0, 3072 );
//		TSockXfrLength len;
//		iSocket.RecvOneOrMore(iPtrHBuf, 0, aStatus, len);
//		iReadIdx = 0;
//		iReadState = 1;
//		return this;
//	}
//	case 1:
//	{
//		if (iStateMachine->LastError() != KErrNone) {
//			LOG(Log::Printf(_L("ReadState 1 Return Err")));
//			User::RequestComplete(pStatus, ret);
//			return NULL;
//		}
//		LOG(Log::Printf(_L("ReadState 1")));
//		TInt res = iMbedContext.Read((unsigned char*) iData->Ptr(), iData->MaxLength());
//		if (res == 0 || res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
//			ret = KErrEof;
//			LOG(Log::Printf(_L("CRecvEvent::ProcessL() Eof")));
//			break;
//		}
//		if (res == MBEDTLS_ERR_SSL_WANT_READ) {
//			if (iReadIdx >= iPtrHBuf.Length()) {
//				iReadState = 0;
//				LOG(Log::Printf(_L("ReadState 1 RepeatA")));
//			} else {
//				iReadState = 1;
//				LOG(Log::Printf(_L("ReadState 1 RepeatB")));
//			}
//			User::RequestComplete(pStatus, KErrNone);
//			return this;
//		}
//		if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
//			iReadState = 1;
//			LOG(Log::Printf(_L("ReadState 1 RepeatC")));
//			User::RequestComplete(pStatus, KErrNone);
//			return this;
//		}
//		if (res < 0) {
//			ret = KErrGeneral;
//			LOG(Log::Printf(_L("CRecvEvent::ProcessL() Err: %x"), -res));
//			break;
//		}
//	}
//	break;
//	}
	TInt res = iMbedContext.Read((unsigned char*) iData->Ptr(), iData->MaxLength());
	if (res == 0 || res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		ret = KErrEof;
		LOG(Log::Printf(_L("CRecvEvent::ProcessL() Eof")));
	} else if (res < 0) {
		ret = KErrGeneral;
		LOG(Log::Printf(_L("CRecvEvent::ProcessL() Err: %x"), -res));
	}
	
	User::RequestComplete(pStatus, ret);
		
	LOG(Log::Printf(_L("-CRecvEvent::ProcessL()")));
	return NULL;
}
