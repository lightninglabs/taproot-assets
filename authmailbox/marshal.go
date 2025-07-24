package authmailbox

import (
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
)

// A series of type aliases to shorten the code and make it more readable, in
// both the client and server code.
type (
	serverStream = mboxrpc.Mailbox_ReceiveMessagesServer
	clientStream = mboxrpc.Mailbox_ReceiveMessagesClient

	toServerMsg = mboxrpc.ReceiveMessagesRequest
	toClientMsg = mboxrpc.ReceiveMessagesResponse

	reqTypeInit    = mboxrpc.ReceiveMessagesRequest_Init
	reqTypeAuthSig = mboxrpc.ReceiveMessagesRequest_AuthSig

	respTypeChallenge   = mboxrpc.ReceiveMessagesResponse_Challenge
	respTypeAuthSuccess = mboxrpc.ReceiveMessagesResponse_AuthSuccess
	respTypeMessages    = mboxrpc.ReceiveMessagesResponse_Messages
	respTypeEndOfStream = mboxrpc.ReceiveMessagesResponse_Eos
)

// MarshalMessage converts a Message to its gRPC representation.
func MarshalMessage(msg *Message) *mboxrpc.MailboxMessage {
	return &mboxrpc.MailboxMessage{
		MessageId:        msg.ID,
		EncryptedPayload: msg.EncryptedPayload,
		ArrivalTimestamp: msg.ArrivalTimestamp.Unix(),
	}
}
