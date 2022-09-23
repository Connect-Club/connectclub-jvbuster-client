package jvbuster

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
)

const emptyJson = "{}"

func createEndpointMessage(log *logrus.Entry, msgPayload interface{}, to string) string {
	msg := map[string]interface{}{
		"colibriClass": "EndpointMessage",
		"to":           to,
		"msgPayload":   msgPayload,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.WithError(err).Error("error while converting to JSON")
		return emptyJson
	}
	return string(msgBytes)
}

func createSubscribedEndpointsChangedEvent(log *logrus.Entry, subscribedEndpointsUUID map[ /*EndpointUUID*/ string]VideoConstraint) string {
	msg := map[string]interface{}{
		"colibriClass":            "SubscribedEndpointsChangedEvent",
		"subscribedEndpointsUUID": subscribedEndpointsUUID,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.WithError(err).Error("error while converting to JSON")
		return emptyJson
	}
	return string(msgBytes)
}

func createPinnedUUIDEndpointsChangedEvent(log *logrus.Entry, pinnedUUIDEndpoints []string) string {
	msg := map[string]interface{}{
		"colibriClass":        "PinnedUUIDEndpointsChangedEvent",
		"pinnedUUIDEndpoints": pinnedUUIDEndpoints,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.WithError(err).Error("error while converting to JSON")
		return emptyJson
	}
	return string(msgBytes)
}

func createSubscriptionTypeChangedEvent(log *logrus.Entry, subscriptionType SubscriptionType) string {
	msg := map[string]interface{}{
		"colibriClass": "SubscriptionTypeChangedEvent",
		"value":        subscriptionType.JvbString(),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.WithError(err).Error("error while converting to JSON")
		return emptyJson
	}
	return string(msgBytes)
}

func createReceiverVideoConstraint(log *logrus.Entry, maxFrameHeight int, maxFrameTemporalLayerId int) string {
	msg := map[string]interface{}{
		"colibriClass":            "ReceiverVideoConstraint",
		"maxFrameHeight":          maxFrameHeight,
		"maxFrameTemporalLayerId": maxFrameTemporalLayerId,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.WithError(err).Error("error while converting to JSON")
		return emptyJson
	}
	return string(msgBytes)
}
