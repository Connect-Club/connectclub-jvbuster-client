package jvbuster

import (
	"errors"
)

var ServerError = errors.New("server error")
var InactiveClientError = errors.New("inactive client")
var StartOnActiveClientError = errors.New("cannot start already started client")
var UnknownPeerConnectionError = errors.New("unknown peer connection")
var AllOffersHaveToBeAcceptedError = errors.New("all SDP offers have to be accepted")
var BadTokenError = errors.New("bad token")
var NotFoundError = errors.New("endpoint expired")
