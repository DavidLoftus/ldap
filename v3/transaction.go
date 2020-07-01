package ldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	startTransactionOID = "1.3.6.1.1.21.1"
	endTransactionOID   = "1.3.6.1.1.21.3"
)

type startTransactionRequest struct{}

func (startTransactionRequest) appendTo(packet *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start Transaction Extended Operation")
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, startTransactionOID, "Extended Request Name: Start Transaction"))
	packet.AppendChild(pkt)
	return nil
}

// StartTransaction sends a Start Transaction extended request as defined by RFC 5805 https://tools.ietf.org/html/rfc5805
// Returns the transaction identifier to use with TransactionSpecificationControl & EndTransaction.
func (l *Conn) StartTransaction() (string, error) {
	msgCtx, err := l.doRequest(startTransactionRequest{})
	if err != nil {
		return "", err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return "", err
	}

	pkt := packet.Children[1]
	if pkt.Tag != ApplicationExtendedResponse {
		return "", &Error{
			ResultCode: ErrorUnexpectedResponse,
			Err:        fmt.Errorf("unexpected response: %d", pkt.Tag),
		}
	}

	err = GetLDAPError(packet)
	if err != nil {
		return "", err
	}

	extendedResponse := packet.Children[1] //extendedResponse := packet.Children[1]
	for _, child := range extendedResponse.Children {
		if child.Tag == 11 {
			return child.Value.(string), nil
		}
	}
	return "", &Error{
		ResultCode: ErrorUnexpectedResponse,
		Err:        fmt.Errorf("no responseValue found"),
	}
}

type EndTransactionRequest struct {
	Commit     bool
	Identifier string
}

func (r *EndTransactionRequest) appendTo(packet *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "End Transaction Extended Operation")
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, endTransactionOID, "Extended Request Name: End Transaction"))

	extendedRequestValue := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "Extended Request Value: End Transaction Request")
	passwordModifyRequestValue := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Password Modify Request")
	if !r.Commit {
		passwordModifyRequestValue.AppendChild(ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, 0, r.Commit, "Commit"))
	}
	passwordModifyRequestValue.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, r.Identifier, "Identifier"))

	extendedRequestValue.AppendChild(passwordModifyRequestValue)

	pkt.AppendChild(extendedRequestValue)
	packet.AppendChild(pkt)
	return nil
}

// NewCommitTransactionRequest creates a new EndTransactionRequest to commit a transaction.
//
// identifier is the string returned by StartTransaction
func NewCommitTransactionRequest(identifier string) *EndTransactionRequest {
	return &EndTransactionRequest{
		Commit:     true,
		Identifier: identifier,
	}
}

// NewAbortTransactionRequest creates a new EndTransactionRequest to abort a transaction.
//
// identifier is the string returned by StartTransaction
func NewAbortTransactionRequest(identifier string) *EndTransactionRequest {
	return &EndTransactionRequest{
		Commit:     false,
		Identifier: identifier,
	}
}

// EndTransaction sends an End Transaction extended request as defined by RFC 5805 https://tools.ietf.org/html/rfc5805
func (l *Conn) EndTransaction(r *EndTransactionRequest) error {
	msgCtx, err := l.doRequest(r)
	if err != nil {
		return err
	}

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return err
	}

	if packet.Children[1].Tag != ApplicationExtendedResponse {
		return &Error{
			ResultCode: ErrorUnexpectedResponse,
			Err:        fmt.Errorf("unexpected response: %d", packet.Children[1].Tag),
		}
	}

	if err := GetLDAPError(packet); err != nil {
		return err
	}
	return nil
}
