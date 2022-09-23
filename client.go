package jvbuster

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gitlab.com/connect.club/jitsi/connectclub-jvbuster-client.git/internal/volatile"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

type SubscriptionType uint

//goland:noinspection GoUnusedConst
const (
	NormalSubscription SubscriptionType = iota
	AudioSubscription
	MixedAudioSubscription
)

func (d SubscriptionType) JvbString() string {
	return [...]string{
		"NORMAL",
		"AUDIO",
		"MIXED_AUDIO",
	}[d]
}

type SdpOfferMeta struct {
	AudioTracks []string
	VideoTracks []string
}

type SdpOffer struct {
	Primary bool
	Text    string
	Meta    map[ /*StreamId*/ string]SdpOfferMeta
}

type VideoConstraint struct {
	OffVideo bool `json:"offVideo"`
	LowRes   bool `json:"lowRes"`
	LowFps   bool `json:"lowFps"`
}

type jwtTokenPayload struct {
	Endpoint      string
	ConferenceGid string
}

type sdpMediaDescription struct {
	channelId string
	mediaId   string
	typ       string
	endpoint  string
	enabled   bool
	text      string
}

type sdpGeneratorData struct {
	sessionId                     int64
	sessionVersion                int64
	conferenceId                  string
	primary                       bool
	applicationMediaDescription   sdpMediaDescription
	mainAudioMediaDescription     sdpMediaDescription
	mainVideoMediaDescription     sdpMediaDescription
	participantsMediaDescriptions []sdpMediaDescription
	subscribedEndpointsUUID       map[ /*EndpointUUID*/ string]VideoConstraint
	accepted                      bool
}

type dataChannelInfo struct {
	available    bool
	firstMessage *sync.WaitGroup
}

type Client struct {
	log                               *logrus.Entry
	httpClient                        *http.Client
	id                                string
	speaker                           bool
	guestEndpoint                     string
	address, token, endpoint          string
	onNewMessageForDataChannel        func(peerConnectionId string, msg string)
	onNewSdpOffers                    func(sdpOffers map[ /*PeerConnectionId*/ string]SdpOffer, accepted func() error)
	onExpired                         func()
	onEndpoints                       func(endpoints map[ /*PeerConnectionId*/ string][]string)
	onNewEndpointMessage              func(from string, msgPayload map[string]interface{})
	offers                            *volatile.Value[[]Offer]
	sdpGeneratorDataForPeerConnection map[ /*PeerConnectionId*/ string]sdpGeneratorData
	dataChannelInfoForPeerConnection  map[ /*PeerConnectionId*/ string]dataChannelInfo
	subscribedEndpoints               *volatile.Value[map[string]VideoConstraint]
	screenVideoConstraint             *volatile.Value[VideoConstraint]
	availableEndpoints                map[ /*PeerConnectionId*/ string]StringSet
	videoBandwidth                    int
	audioBandwidth                    int

	globalLock sync.Mutex

	callbackCh      chan func()
	callbackCloseCh chan interface{}
	callbackDoneCh  chan interface{}

	isActive *volatile.Value[bool]

	updateOfferTask      *Task
	sendNewSdpOffersTask *Task

	simulcastSupported bool
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (c *Client) IsActive() bool {
	return c.isActive.Load()
}

//goland:noinspection GoUnusedExportedFunction
func NewClient(
	address, token string,
	onNewMessageForDataChannel func(peerConnectionId string, msg string),
	onNewSdpOffers func(sdpOffers map[ /*PeerConnectionId*/ string]SdpOffer, accepted func() error),
	onExpired func(),
	/*for web client*/ onEndpoints func(endpoints map[ /*PeerConnectionId*/ string][]string),
	/*for web client*/ onNewEndpointMessage func(from string, msgPayload map[string]interface{}),
	videoBandwidth int,
	audioBandwidth int,
) (*Client, error) {
	clientId := strconv.FormatUint(rand.Uint64(), 10)

	log := logrus.WithField("clientId", clientId)
	log.Info("🚀")

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		err := fmt.Errorf("%w, token contains %d parts, instead of 3", BadTokenError, len(tokenParts))
		return nil, err
	}
	tokenPayloadJson, err := base64.RawStdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		err := fmt.Errorf("%w, can not decode second part of token", BadTokenError)
		return nil, err
	}
	var tokenPayload jwtTokenPayload
	if err := json.Unmarshal(tokenPayloadJson, &tokenPayload); err != nil {
		err := fmt.Errorf("%w, unmarshal token payload error", BadTokenError)
		return nil, err
	}

	client := new(Client)
	client.httpClient = &http.Client{Timeout: time.Second * 10}
	client.log = log
	client.id = clientId
	client.isActive = volatile.NewValue(false)
	client.address = address
	client.token = token
	client.endpoint = tokenPayload.Endpoint
	client.onNewMessageForDataChannel = onNewMessageForDataChannel
	client.onNewSdpOffers = onNewSdpOffers
	client.onExpired = onExpired
	client.onEndpoints = onEndpoints
	client.onNewEndpointMessage = onNewEndpointMessage
	client.offers = volatile.NewValue[[]Offer](nil)
	client.subscribedEndpoints = volatile.NewValue[map[string]VideoConstraint](nil)
	client.screenVideoConstraint = volatile.NewValue(VideoConstraint{})
	if videoBandwidth == 0 {
		videoBandwidth = 200
	}
	client.videoBandwidth = videoBandwidth
	if audioBandwidth == 0 {
		audioBandwidth = 16
	}
	client.audioBandwidth = audioBandwidth
	return client, nil
}

func (c *Client) IsSpeaker() bool {
	return c.speaker
}

func getOffers(body []byte) ([]Offer, error) {
	var offers []Offer
	if err := json.Unmarshal(body, &offers); err != nil {
		return nil, fmt.Errorf("%w, cannot unmarshal offers, reason = %v", ServerError, err.Error())
	}
	for i, offer := range offers {
		offer.endpointToUuid = make(map[string]string)
		for _, endpoint := range offer.Endpoints {
			offer.endpointToUuid[endpoint.Id] = endpoint.Uuid
		}
		offers[i] = offer
	}
	return offers, nil
}

//go:embed templates/header.tmpl
var headerTemplateText string

//go:embed templates/application-media.tmpl
var applicationChannelTemplateText string

//go:embed templates/main-audio-media.tmpl
var mainAudioChannelTemplateText string

//go:embed templates/main-video-media.tmpl
var mainVideoChannelTemplateText string

//go:embed templates/participant-audio-media.tmpl
var participantAudioChannelTemplateText string

//go:embed templates/participant-video-media.tmpl
var participantVideoChannelTemplateText string

var templatedFuncMap = template.FuncMap{
	"ToLower": strings.ToLower,
	"Join": func(sep string, elems []string) string {
		return strings.Join(elems, sep)
	},
	"IntsToStrings": func(intElems []int) []string {
		stringElems := make([]string, len(intElems))
		for i, v := range intElems {
			stringElems[i] = strconv.Itoa(v)
		}
		return stringElems
	},
	"Ints64ToStrings": func(intElems []int64) []string {
		stringElems := make([]string, len(intElems))
		for i, v := range intElems {
			stringElems[i] = strconv.FormatInt(v, 10)
		}
		return stringElems
	},
}

var headerTemplate, _ = template.New("header").Funcs(templatedFuncMap).Parse(headerTemplateText)
var applicationMediaTemplate, _ = template.New("application-media").Funcs(templatedFuncMap).Parse(applicationChannelTemplateText)
var mainAudioMediaTemplate, _ = template.New("main-audio-media").Funcs(templatedFuncMap).Parse(mainAudioChannelTemplateText)
var mainVideoMediaTemplate, _ = template.New("main-video-media").Funcs(templatedFuncMap).Parse(mainVideoChannelTemplateText)
var participantAudioTemplate, _ = template.New("participant-audio-media").Funcs(templatedFuncMap).Parse(participantAudioChannelTemplateText)
var participantVideoTemplate, _ = template.New("participant-video-media").Funcs(templatedFuncMap).Parse(participantVideoChannelTemplateText)

func needNewSdpOfferText(offer *Offer, prevMediaIds StringSet, subscribedEndpoints map[string]VideoConstraint) bool {
	allAvailableMediaIds := NewStringSetSized(len(offer.AudioChannels) + len(offer.VideoChannels))
	for _, channel := range offer.AudioChannels {
		allAvailableMediaIds.Add(channel.Id)
	}
	for _, channel := range offer.VideoChannels {
		allAvailableMediaIds.Add(channel.Id)
	}
	for prevMediaId := range prevMediaIds {
		if !allAvailableMediaIds.Contains(prevMediaId) {
			return true
		}
	}

	fn := func(channels []Channel, mType string) bool {
		for _, channel := range channels {
			_, isPinned := subscribedEndpoints[channel.Endpoint]
			if !isPinned && !strings.HasPrefix(channel.Endpoint, "screen-") {
				continue
			}
			mediaId := channel.Id
			if !prevMediaIds.Contains(mediaId) {
				return true
			}
		}
		return false
	}
	return fn(offer.AudioChannels, "audio") ||
		fn(offer.VideoChannels, "video")
}

func (offer *Offer) getPeerConnectionId() string {
	return fmt.Sprintf("%s-%s", offer.Ufrag, offer.VideobridgeId)
}

func (sdpGeneratorData *sdpGeneratorData) generateMeta(subscribedEndpoints map[ /*EndpointId*/ string]VideoConstraint) map[ /*endpoint|streamId*/ string]SdpOfferMeta {
	streamToAudioTracks := make(map[ /*endpoint|streamId*/ string][]string)
	streamToVideoTracks := make(map[ /*endpoint|streamId*/ string][]string)
	for _, v := range sdpGeneratorData.participantsMediaDescriptions {

		if _, endpointSubscribed := subscribedEndpoints[v.endpoint]; v.enabled && (endpointSubscribed || strings.HasPrefix(v.endpoint, "screen-")) {
			if v.typ == "audio" {
				tracks, ok := streamToAudioTracks[v.endpoint]
				if ok {
					tracks = append(tracks, v.channelId)
				} else {
					tracks = []string{v.channelId}
				}
				streamToAudioTracks[v.endpoint] = tracks
			} else if v.typ == "video" {
				tracks, ok := streamToVideoTracks[v.endpoint]
				if ok {
					tracks = append(tracks, v.channelId)
				} else {
					tracks = []string{v.channelId}
				}
				streamToVideoTracks[v.endpoint] = tracks
			}
		}
	}

	meta := make(map[string]SdpOfferMeta)
	for stream, audioTracks := range streamToAudioTracks {
		videoTracks, hasVideoTracks := streamToVideoTracks[stream]
		if !hasVideoTracks {
			videoTracks = []string{}
		}
		meta[stream] = SdpOfferMeta{
			AudioTracks: audioTracks,
			VideoTracks: videoTracks,
		}
	}
	for stream, videoTracks := range streamToVideoTracks {
		if _, hasStreasm := meta[stream]; hasStreasm {
			continue
		}
		meta[stream] = SdpOfferMeta{
			AudioTracks: []string{},
			VideoTracks: videoTracks,
		}
	}

	return meta
}

func (c *Client) toSdpOffer(primary bool, offer *Offer, subscribedEndpoints map[ /*EndpointId*/ string]VideoConstraint, screenVideoConstraint VideoConstraint) (*SdpOffer, string) {
	builder := strings.Builder{}
	peerConnectionId := offer.getPeerConnectionId()
	currentSdpGeneratorData, sdpGeneratorFound := c.sdpGeneratorDataForPeerConnection[peerConnectionId]
	if !sdpGeneratorFound {
		applicationMid := offer.SctpConnectionId
		mainAudioMid := offer.PrimaryAudioChannel.Id
		mainVideoMid := offer.PrimaryVideoChannel.Id

		builder.Reset()
		err := applicationMediaTemplate.Execute(&builder, ApplicationChannelTemplateData{
			MediaId:    applicationMid,
			Candidates: offer.Candidates,
		})
		if err != nil {
			c.panic(fmt.Errorf("application sdp generation error: %w", err))
		}
		applicationMediaDescriptionText := builder.String()

		builder.Reset()
		err = mainAudioMediaTemplate.Execute(&builder, MainChannelTemplateData{
			MediaId:    mainAudioMid,
			Direction:  offer.PrimaryAudioChannel.Direction,
			Sources:    offer.PrimaryAudioChannel.Sources,
			Candidates: offer.Candidates,
			Bandwidth:  c.audioBandwidth,
		})
		if err != nil {
			c.panic(fmt.Errorf("main audio sdp generation error: %w", err))
		}
		mainAudioMediaDescriptionText := builder.String()

		builder.Reset()
		err = mainVideoMediaTemplate.Execute(&builder, MainChannelTemplateData{
			MediaId:    mainVideoMid,
			Direction:  offer.PrimaryVideoChannel.Direction,
			Sources:    offer.PrimaryVideoChannel.Sources,
			Candidates: offer.Candidates,
			Bandwidth:  c.videoBandwidth,
		})
		if err != nil {
			c.panic(fmt.Errorf("main video sdp generation error: %w", err))
		}
		mainVideoMediaDescriptionText := builder.String()
		builder.Reset()

		currentSdpGeneratorData = sdpGeneratorData{
			sessionId:      time.Now().Unix(),
			conferenceId:   offer.ConferenceId,
			primary:        primary,
			sessionVersion: 1,
			applicationMediaDescription: sdpMediaDescription{
				mediaId:   applicationMid,
				channelId: offer.SctpConnectionId,
				text:      applicationMediaDescriptionText,
			},
			mainAudioMediaDescription: sdpMediaDescription{
				mediaId:   mainAudioMid,
				channelId: offer.PrimaryAudioChannel.Id,
				text:      mainAudioMediaDescriptionText,
			},
			mainVideoMediaDescription: sdpMediaDescription{
				mediaId:   mainVideoMid,
				channelId: offer.PrimaryVideoChannel.Id,
				text:      mainVideoMediaDescriptionText,
			},
			participantsMediaDescriptions: make([]sdpMediaDescription, 0, 25),
			subscribedEndpointsUUID:       make(map[string]VideoConstraint),
		}
		c.dataChannelInfoForPeerConnection[peerConnectionId] = dataChannelInfo{
			available:    false,
			firstMessage: &sync.WaitGroup{},
		}
		c.dataChannelInfoForPeerConnection[peerConnectionId].firstMessage.Add(1)
	} else {
		if !currentSdpGeneratorData.accepted {
			c.log.Warn("currentSdpGeneratorData.accepted == false")
			return nil, peerConnectionId
		}
		allMediaIds := NewStringSetSized(len(currentSdpGeneratorData.participantsMediaDescriptions))
		for _, mediaDesc := range currentSdpGeneratorData.participantsMediaDescriptions {
			if mediaDesc.enabled {
				allMediaIds.Add(mediaDesc.mediaId)
			}
		}
		if !needNewSdpOfferText(offer, allMediaIds, subscribedEndpoints) {
			currentSdpGeneratorData.subscribedEndpointsUUID = make(map[string]VideoConstraint)
			for endpoint, videoConstraint := range subscribedEndpoints {
				endpointUuid, ok := offer.endpointToUuid[endpoint]
				if ok {
					currentSdpGeneratorData.subscribedEndpointsUUID[endpointUuid] = videoConstraint
				}
			}
			for endpointId, endpointUuid := range offer.endpointToUuid {
				if strings.HasPrefix(endpointId, "screen-") {
					currentSdpGeneratorData.subscribedEndpointsUUID[endpointUuid] = screenVideoConstraint
				}
			}
			c.sdpGeneratorDataForPeerConnection[peerConnectionId] = currentSdpGeneratorData
			return &SdpOffer{Primary: primary, Meta: currentSdpGeneratorData.generateMeta(subscribedEndpoints)}, peerConnectionId
		}
		currentSdpGeneratorData.sessionVersion++
	}

	allMediaIds := NewStringSetSized(len(offer.AudioChannels) + len(offer.VideoChannels))
	for _, channel := range offer.AudioChannels {
		allMediaIds.Add(channel.Id)
	}
	for _, channel := range offer.VideoChannels {
		allMediaIds.Add(channel.Id)
	}

	pinnedMediaIds := NewStringSet()

	currentSdpGeneratorData.subscribedEndpointsUUID = make(map[string]VideoConstraint)
	processChannels := func(mType string, template *template.Template, channels []Channel) {
		for _, channel := range channels {
			uuidEndpoint, ok := offer.endpointToUuid[channel.Endpoint]
			if !ok {
				c.log.Warnf("Can not find uuid for endpoint = %s", channel.Endpoint)
				continue
			}
			videoConstraint, isPinned := subscribedEndpoints[channel.Endpoint]
			if !isPinned && !strings.HasPrefix(channel.Endpoint, "screen-") {
				continue
			}
			mediaId := channel.Id
			pinnedMediaIds.Add(mediaId)
			currentSdpGeneratorData.subscribedEndpointsUUID[uuidEndpoint] = videoConstraint
			alreadyRendered := false
			firstEmptyPosition := -1
			for i, participantsMediaDescription := range currentSdpGeneratorData.participantsMediaDescriptions {
				if participantsMediaDescription.typ != mType {
					continue
				}
				if participantsMediaDescription.enabled {
					if participantsMediaDescription.endpoint == channel.Endpoint && participantsMediaDescription.mediaId == mediaId {
						alreadyRendered = true
						break
					}
				} else if firstEmptyPosition == -1 {
					firstEmptyPosition = i
				}
			}
			if !alreadyRendered {
				builder.Reset()
				if err := template.Execute(&builder, ParticipantChannelTemplateData{
					MediaId:    mediaId,
					Id:         channel.Id,
					Endpoint:   channel.Endpoint,
					SsrcGroups: channel.SsrcGroups,
					Ssrcs:      channel.Ssrcs,
					Candidates: offer.Candidates,
				}); err != nil {
					c.panic(fmt.Errorf("participant sdp generation error: %w", err))
				}
				newSdpMediaDescription := sdpMediaDescription{
					mediaId:   mediaId,
					channelId: channel.Id,
					typ:       mType,
					endpoint:  channel.Endpoint,
					enabled:   true,
					text:      builder.String(),
				}
				if firstEmptyPosition >= 0 {
					currentSdpGeneratorData.participantsMediaDescriptions[firstEmptyPosition] = newSdpMediaDescription
				} else {
					currentSdpGeneratorData.participantsMediaDescriptions = append(currentSdpGeneratorData.participantsMediaDescriptions, newSdpMediaDescription)
				}
			}
		}
	}
	processChannels("audio", participantAudioTemplate, offer.AudioChannels)
	processChannels("video", participantVideoTemplate, offer.VideoChannels)

	for i, participantsMediaDescription := range currentSdpGeneratorData.participantsMediaDescriptions {
		if !participantsMediaDescription.enabled || allMediaIds.Contains(participantsMediaDescription.mediaId) {
			continue
		}
		participantsMediaDescription.text = ""
		participantsMediaDescription.enabled = false
		currentSdpGeneratorData.participantsMediaDescriptions[i] = participantsMediaDescription
	}

	mediaIds := make([]string, 0, len(currentSdpGeneratorData.participantsMediaDescriptions)+3)
	mediaIds = append(mediaIds, currentSdpGeneratorData.applicationMediaDescription.mediaId)
	mediaIds = append(mediaIds, currentSdpGeneratorData.mainAudioMediaDescription.mediaId)
	mediaIds = append(mediaIds, currentSdpGeneratorData.mainVideoMediaDescription.mediaId)
	for _, v := range currentSdpGeneratorData.participantsMediaDescriptions {
		if !v.enabled {
			continue
		}
		mediaIds = append(mediaIds, v.mediaId)
	}

	builder.Reset()
	err := headerTemplate.Execute(&builder, HeaderTemplateData{
		SessionId:      currentSdpGeneratorData.sessionId,
		SessionVersion: currentSdpGeneratorData.sessionVersion,
		ConferenceId:   currentSdpGeneratorData.conferenceId,
		Ufrag:          offer.Ufrag,
		Pwd:            offer.Pwd,
		MediaIds:       mediaIds,
		Fingerprints:   offer.Fingerprints,
	})
	if err != nil {
		c.panic(fmt.Errorf("header sdp generation error: %w", err))
	}
	builder.WriteString(currentSdpGeneratorData.applicationMediaDescription.text)
	builder.WriteString(currentSdpGeneratorData.mainAudioMediaDescription.text)
	builder.WriteString(currentSdpGeneratorData.mainVideoMediaDescription.text)
	for _, v := range currentSdpGeneratorData.participantsMediaDescriptions {
		if v.enabled {
			builder.WriteString(v.text)
		} else {
			builder.WriteString(fmt.Sprintf("m=%s 0 RTP/SAVPF 0\r\na=mid:%v\r\n", v.typ, v.mediaId))
		}
	}

	currentSdpGeneratorData.accepted = false
	c.sdpGeneratorDataForPeerConnection[peerConnectionId] = currentSdpGeneratorData
	if currentSdpGeneratorData.sessionVersion == 1 {
		c.availableEndpoints[peerConnectionId] = NewStringSet()
	}
	return &SdpOffer{
		Primary: primary,
		Text:    builder.String(),
		Meta:    currentSdpGeneratorData.generateMeta(subscribedEndpoints),
	}, peerConnectionId
}

func (c *Client) repeatableHttpRequestWithContext(ctx context.Context, method, url string, body io.Reader, headers map[string]string) ([]byte, http.Header, error) {
	for {
		req, createRequestErr := http.NewRequestWithContext(ctx, method, url, body)
		if createRequestErr != nil {
			c.log.WithError(createRequestErr).Panic("new request error")
		}
		req.Header.Add("Authorization", "Bearer "+c.token)
		if len(c.guestEndpoint) > 0 {
			req.Header.Add("guest-endpoint", c.guestEndpoint)
		}
		req.Header.Add("jvbuster-client-id", c.id)
		if headers != nil {
			for k, v := range headers {
				req.Header.Add(k, v)
			}
		}

		var body []byte
		var header http.Header

		resp, requestErr := c.httpClient.Do(req)
		if requestErr != nil {
			c.log.WithError(requestErr).Info("http request failed")
		} else {
			header = nil
			body, readBodyErr := ioutil.ReadAll(resp.Body)
			if readBodyErr != nil {
				_ = resp.Body.Close()
				c.log.WithError(readBodyErr).Info("cannot read response body")
				body = nil
				goto repeat
			}
			header = resp.Header
			if err := resp.Body.Close(); err != nil {
				c.log.WithError(err).Warn("cannot close response body")
			}
			if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
				//it makes no sense to repeat
				if resp.StatusCode == 404 {
					return body, header, NotFoundError
				} else {
					return body, header, fmt.Errorf("%w, response status = %v", BadTokenError, resp.Status)
				}
			} else if resp.StatusCode != 200 {
				c.log.Infof("incorrect response. StatusCode=%d, Status=%s", resp.StatusCode, resp.Status)
				goto repeat
			}
			return body, header, nil
		}
	repeat:
		select {
		case <-ctx.Done():
			return body, header, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (c *Client) Start(ctx context.Context, speaker bool, guestEndpoint string) error {
	c.log.Info("🚀")

	c.globalLock.Lock()
	c.log.Info("globalLock.Lock()")
	defer c.log.Info("globalLock.Unlock()")
	defer c.globalLock.Unlock()

	if c.isActive.Load() {
		return c.reportErr(StartOnActiveClientError)
	}

	c.speaker = speaker
	c.guestEndpoint = guestEndpoint
	// there might be idle connections that created for inactive network interface
	// we should close them because they are dead
	c.httpClient.CloseIdleConnections()
	offersBody, header, err := c.repeatableHttpRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/signaling-new/new-offers?speaker=%t", c.address, speaker),
		nil,
		nil,
	)
	if err != nil {
		select {
		case <-ctx.Done():
			return err
		default:
			c.log.WithError(err).Error("get new offers failed")
			return c.reportErr(err)
		}
	}

	c.sdpGeneratorDataForPeerConnection = make(map[ /*PeerConnectionId*/ string]sdpGeneratorData)
	c.dataChannelInfoForPeerConnection = make(map[ /*PeerConnectionId*/ string]dataChannelInfo)
	c.availableEndpoints = make(map[ /*PeerConnectionId*/ string]StringSet)

	c.updateOfferTask = CreateTask(c.updateOffers, 500*time.Millisecond, true)
	c.sendNewSdpOffersTask = CreateTask(c.sendNewSdpOffers, 500*time.Millisecond, true)

	c.offers.Store([]Offer{})
	c.subscribedEndpoints.Store(map[string]VideoConstraint{})

	c.simulcastSupported = header.Get("Webrtc-Simulcast") == "true"
	if offers, err := getOffers(offersBody); err != nil {
		return err
	} else {
		c.offers.Store(offers)
	}
	c.isActive.Store(true)

	c.callbackCloseCh = make(chan interface{})
	c.callbackDoneCh = make(chan interface{})
	c.callbackCh = make(chan func(), 1024)

	c.sendNewSdpOffersTask.Run()
	go func() {
		defer close(c.callbackDoneCh)
		for {
			select {
			case <-c.callbackCloseCh:
				return
			case fn, ok := <-c.callbackCh:
				if !ok {
					return
				}
				if !c.isActive.Load() {
					return
				}
				fn()
			}
		}
	}()

	return nil
}

func (c *Client) ModifyAnswer(peerConnectionId, sdpAnswer string) (string, error) {
	c.log.Info("🚀")

	sdpGeneratorData, ok := c.sdpGeneratorDataForPeerConnection[peerConnectionId]
	if !ok {
		return sdpAnswer, fmt.Errorf("%w, peerConnectionId = %v", UnknownPeerConnectionError, peerConnectionId)
	}

	lines := strings.Split(sdpAnswer, "\r\n")

	confIdFound := false
	for _, line := range lines {
		if strings.HasPrefix(line, "a=mid:confId-") {
			confIdFound = true
			break
		}
	}
	if !confIdFound {
		lines = insertConfId(lines, sdpGeneratorData.conferenceId)
	}

	if sdpGeneratorData.primary && c.speaker && c.simulcastSupported {
		lines = mungeSdpForSimulcasting(lines, TwoSimulcastLayers)
	}
	return strings.Join(lines, "\r\n"), nil
}

func (c *Client) SendAnswers(sdpAnswers map[ /*PeerConnectionId*/ string]string) error {
	c.log.Info("🚀")

	if !c.isActive.Load() {
		c.log.Error("inactive client")
		return InactiveClientError
	}

	if len(sdpAnswers) == 0 {
		c.panic(errors.New("sdp answers are empty"))
	}

	bodyBuilder := strings.Builder{}
	for peerConnectionId, sdpAnswer := range sdpAnswers {
		sdpGeneratorData, ok := c.sdpGeneratorDataForPeerConnection[peerConnectionId]
		if !ok {
			return fmt.Errorf("%w, peerConnectionId = %v", UnknownPeerConnectionError, peerConnectionId)
		}
		if sdpGeneratorData.sessionVersion == 1 {
			if bodyBuilder.Len() > 0 {
				bodyBuilder.WriteString("\r\n")
			}
			bodyBuilder.WriteString(sdpAnswer)
		}
	}

	if bodyBuilder.Len() > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		_, _, err := c.repeatableHttpRequestWithContext(
			ctx,
			http.MethodPost,
			fmt.Sprintf("%s/signaling/answers", c.address),
			strings.NewReader(bodyBuilder.String()),
			map[string]string{"Content-Type": "text/plain;charset=utf-8"},
		)
		cancel()
		if err != nil {
			return err
		}
	}

	for peerConnectionId := range sdpAnswers {
		if err := c.markSdpOfferAsAccepted(peerConnectionId); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) ModifyAndSendAnswers(sdpAnswers map[ /*PeerConnectionId*/ string]string) (map[string]string, error) {
	c.log.Info("🚀")

	newSdpAnswers := make(map[ /*PeerConnectionId*/ string]string)

	for peerConnectionId, sdpAnswer := range sdpAnswers {
		if newSdpAnswer, err := c.ModifyAnswer(peerConnectionId, sdpAnswer); err != nil {
			return nil, err
		} else {
			newSdpAnswers[peerConnectionId] = newSdpAnswer
		}
	}

	if err := c.SendAnswers(newSdpAnswers); err != nil {
		return nil, err
	}

	return newSdpAnswers, nil
}

func (c *Client) markSdpOfferAsAccepted(peerConnectionId string) error {
	sdpGeneratorData, ok := c.sdpGeneratorDataForPeerConnection[peerConnectionId]
	if !ok {
		return fmt.Errorf("%w, peerConnectionId = %v", UnknownPeerConnectionError, peerConnectionId)
	}
	if !sdpGeneratorData.accepted {
		sdpGeneratorData.accepted = true
		c.sdpGeneratorDataForPeerConnection[peerConnectionId] = sdpGeneratorData
	}
	return nil
}

func (c *Client) Stop() {
	if !c.isActive.Load() {
		return
	}

	c.globalLock.Lock()
	c.log.Info("globalLock.Lock()")
	defer c.log.Info("globalLock.Unlock()")
	defer c.globalLock.Unlock()

	if !c.isActive.Load() {
		return
	}

	c.isActive.Store(false)

	for peerConnectionId, dataChannelInfo := range c.dataChannelInfoForPeerConnection {
		if !dataChannelInfo.available {
			dataChannelInfo.available = true
			dataChannelInfo.firstMessage.Done()
			c.dataChannelInfoForPeerConnection[peerConnectionId] = dataChannelInfo
		}
	}

	close(c.callbackCloseCh)

	select {
	case <-time.After(time.Second * 10):
		c.log.Panic("too long waiting callbackDoneCh")
	case <-c.callbackDoneCh:
		c.log.Info("callbackDoneCh closed")
	}

	if err := c.updateOfferTask.Stop(time.Second * 10); err != nil {
		c.log.WithError(err).Panic("cannot stop updateOfferTask")
	} else {
		c.log.Info("updateOfferTask stopped")
	}
	if err := c.sendNewSdpOffersTask.Stop(time.Second * 10); err != nil {
		c.log.WithError(err).Panic("cannot stop sendNewSdpOffersTask")
	} else {
		c.log.Info("sendNewSdpOffersTask stopped")
	}
}

func (c *Client) Destroy() {
	c.log.Info("🚀")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	_, _, err := c.repeatableHttpRequestWithContext(ctx, http.MethodDelete, fmt.Sprintf("%s/signaling-new", c.address), nil, nil)
	cancel()
	if err != nil {
		c.log.WithError(err).Warn("destroy jvbuster client failed")
	}
	c.httpClient.CloseIdleConnections()
}

func (c *Client) updateOffers(ctx context.Context) {
	if !c.isActive.Load() {
		return
	}

	offersBody, _, err := c.repeatableHttpRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/signaling-new/current-offers", c.address),
		nil,
		nil,
	)
	if err != nil {
		select {
		case <-ctx.Done():
		default:
			c.log.WithError(err).Warn("get current offers failed")
			if errors.Is(err, BadTokenError) || errors.Is(err, NotFoundError) {
				c.callOnExpired()
			}
		}
		return
	}

	if offers, err := getOffers(offersBody); err != nil {
		c.log.WithError(err).Error("get offers error")
		_ = c.reportErr(err)
		return
	} else {
		c.offers.Store(offers)
	}
	c.sendNewSdpOffersTask.Run()
}

func (c *Client) ProcessDataChannelMessage(peerConnectionId string, msgJson string) error {
	c.log.Info("🚀")

	c.globalLock.Lock()
	c.log.Info("globalLock.Lock()")
	defer c.log.Info("globalLock.Unlock()")
	defer c.globalLock.Unlock()

	if !c.isActive.Load() {
		c.log.Error("inactive client")
		return InactiveClientError
	}
	dataChannelInfo, knownDataChannelInfo := c.dataChannelInfoForPeerConnection[peerConnectionId]
	if !knownDataChannelInfo {
		c.log.Warnf("skip message for unknown PeerConnectionId=%s", peerConnectionId)
		return nil
	}
	if !dataChannelInfo.available {
		dataChannelInfo.available = true
		dataChannelInfo.firstMessage.Done()
		c.dataChannelInfoForPeerConnection[peerConnectionId] = dataChannelInfo
	}

	var msg map[string]interface{}
	if err := json.Unmarshal([]byte(msgJson), &msg); err != nil {
		return c.reportErr(fmt.Errorf("datachannel message is not json, msg = %v, err = %w", msgJson, err))
	}
	colibriClass, hasColibriClass := msg["colibriClass"].(string)
	if !hasColibriClass {
		return c.reportErr(fmt.Errorf("datachannel message does not have 'colibriClass' property, msg = %v", msgJson))
	}
	endpoint, hasEndpoint := msg["endpoint"].(string)
	if from, hasFrom := msg["from"].(string); colibriClass == "EndpointMessage" && hasFrom && from != c.endpoint {
		if msgPayload, hasMsgPayload := msg["msgPayload"].(map[string]interface{}); hasMsgPayload {
			if c.onNewEndpointMessage != nil {
				c.callOnNewEndpointMessage(from, msgPayload)
			}
		}
	} else if colibriClass == "EndpointConnectivityStatusChangeEvent" && hasEndpoint && endpoint != c.endpoint {
		active, hasActive := msg["active"].(bool)
		if !hasActive {
			return c.reportErr(fmt.Errorf("EndpointConnectivityStatusChangeEvent datachannel message does not have 'active' property, msg = %v", msgJson))
		}
		if active {
			if availableEndpoints, ok := c.availableEndpoints[peerConnectionId]; ok {
				availableEndpoints.Add(endpoint)
				c.sendEndpoints()
			}
			c.updateOfferTask.Run()
		}
	} else if colibriClass == "EndpointExpiredEvent" && hasEndpoint {
		if c.endpoint == endpoint {
			c.callOnExpired()
		} else {
			if availableEndpoints, ok := c.availableEndpoints[peerConnectionId]; ok {
				availableEndpoints.Remove(endpoint)
				c.sendEndpoints()
			}
			c.updateOfferTask.Run()
		}
	} else if colibriClass == "NewVideobridgeAddedToConference" {
		c.updateOfferTask.Run()
	}

	return nil
}

func (c *Client) sendNewSdpOffers(ctx context.Context) {
	c.log.Info("🚀")

	if !c.isActive.Load() {
		return
	}

	offers := c.offers.Load()
	subscribedEndpoints := c.subscribedEndpoints.Load()
	screenVideoConstraint := c.screenVideoConstraint.Load()

	sdpOffers := make(map[string]SdpOffer, len(offers))
	for i, offer := range offers {
		sdpOffer, peerConnectionId := c.toSdpOffer(i == 0, &offer, subscribedEndpoints, screenVideoConstraint)
		if sdpOffer != nil {
			sdpOffers[peerConnectionId] = *sdpOffer
		}
	}

	accepted := make(chan struct{})
	c.callOnNewSdpOffers(sdpOffers, func() error {
		if c.isActive.Load() {
			for peerConnectionId, sdpGeneratorData := range c.sdpGeneratorDataForPeerConnection {
				if sdpGeneratorData.accepted {
					var msg string
					if c.simulcastSupported {
						msg = createSubscribedEndpointsChangedEvent(c.log, sdpGeneratorData.subscribedEndpointsUUID)
					} else {
						pinnedUUIDEndpoints := make([]string, len(sdpGeneratorData.subscribedEndpointsUUID))
						i := 0
						for k := range sdpGeneratorData.subscribedEndpointsUUID {
							pinnedUUIDEndpoints[i] = k
							i++
						}
						msg = createPinnedUUIDEndpointsChangedEvent(c.log, pinnedUUIDEndpoints)
					}
					c.callOnNewMessageForDataChannel(peerConnectionId, msg)
					continue
				}
				return AllOffersHaveToBeAcceptedError
			}
		} else {
			c.log.Info("accepted called on inactive client")
		}
		close(accepted)
		return nil
	})

	select {
	case <-time.After(time.Minute):
		c.log.Panic("too long waiting acceptation")
	case <-accepted:
	case <-ctx.Done():
	}
}

func (c *Client) sendEndpoints() {
	if c.onEndpoints == nil {
		return
	}
	endpoints := make(map[ /*PeerConnectionId*/ string][]string, len(c.availableEndpoints))
	for peerConnectionId, availableEndpoints := range c.availableEndpoints {
		endpoints[peerConnectionId] = availableEndpoints.GetSlice()
	}
	c.callOnEndpoints(endpoints)
}

func (c *Client) Subscribe(endpoints map[string]VideoConstraint, screenVideoConstraint VideoConstraint) {
	c.log.Info("🚀")

	if !c.isActive.Load() {
		return
	}

	c.subscribedEndpoints.Store(endpoints)
	c.screenVideoConstraint.Store(screenVideoConstraint)

	c.sendNewSdpOffersTask.Run()
}

func (c *Client) SetSubscriptionType(subscriptionType SubscriptionType) {
	c.log.Info("🚀")

	c.globalLock.Lock()
	c.log.Info("globalLock.Lock()")
	defer c.log.Info("globalLock.Unlock()")
	defer c.globalLock.Unlock()

	if !c.isActive.Load() {
		return
	}

	msg := createSubscriptionTypeChangedEvent(c.log, subscriptionType)
	c.callOnNewMessageForDataChannel("*", msg)
}

func (c *Client) SendEndpointMessage(msgPayload interface{}, to string) {
	c.log.Info("🚀")

	c.globalLock.Lock()
	c.log.Info("globalLock.Lock()")
	defer c.log.Info("globalLock.Unlock()")
	defer c.globalLock.Unlock()

	if !c.isActive.Load() {
		return
	}

	msg := createEndpointMessage(c.log, msgPayload, to)
	c.callOnNewMessageForDataChannel("*", msg)
}

func (c *Client) SetReceiverVideoConstraint(maxFrameHeight, maxFrameTemporalLayerId int) {
	c.log.Info("🚀")

	c.globalLock.Lock()
	c.log.Info("globalLock.Lock()")
	defer c.log.Info("globalLock.Unlock()")
	defer c.globalLock.Unlock()

	if !c.isActive.Load() {
		return
	}

	msg := createReceiverVideoConstraint(c.log, maxFrameHeight, maxFrameTemporalLayerId)
	c.callOnNewMessageForDataChannel("*", msg)
}

func (c *Client) callOnNewMessageForDataChannel(peerConnectionId string, msg string) {
	if c.onNewMessageForDataChannel == nil {
		c.panic(errors.New("onNewMessageForDataChannel is nil"))
	}
	c.callbackCh <- func() {
		c.log.Info("⤵")
		defer c.log.Info("⤴")

		if peerConnectionId != "*" {
			dataChannelInfo, ok := c.dataChannelInfoForPeerConnection[peerConnectionId]
			if !ok {
				return
			}
			if !dataChannelInfo.available {
				c.log.Info("⏳ waiting for the first data channel message")
				dataChannelInfo.firstMessage.Wait()
				c.log.Info("⌛ the first data channel message received or client closed")
				if !c.isActive.Load() {
					return
				}
			}
		}
		c.onNewMessageForDataChannel(peerConnectionId, msg)
	}
}

func (c *Client) callOnNewSdpOffers(sdpOffers map[ /*PeerConnectionId*/ string]SdpOffer, accepted func() error) {
	if c.onNewSdpOffers == nil {
		c.panic(errors.New("onNewSdpOffers is nil"))
	}
	c.callbackCh <- func() {
		c.log.Info("⤵")
		defer c.log.Info("⤴")

		c.onNewSdpOffers(sdpOffers, accepted)
	}
}

func (c *Client) callOnExpired() {
	if c.onExpired == nil {
		return
	}
	c.callbackCh <- func() {
		c.log.Info("⤵")
		defer c.log.Info("⤴")

		c.onExpired()
	}
}

func (c *Client) callOnEndpoints(endpoints map[ /*PeerConnectionId*/ string][]string) {
	if c.onEndpoints == nil {
		return
	}
	c.callbackCh <- func() {
		c.log.Info("⤵")
		defer c.log.Info("⤴")

		c.onEndpoints(endpoints)
	}
}

func (c *Client) callOnNewEndpointMessage(from string, msgPayload map[string]interface{}) {
	if c.onNewEndpointMessage == nil {
		return
	}
	c.callbackCh <- func() {
		c.log.Info("⤵")
		defer c.log.Info("⤴")

		c.onNewEndpointMessage(from, msgPayload)
	}
}

func (c *Client) reportErr(err error) error {
	go c.postErrorMsg(err.Error())
	return err
}

func (c *Client) panic(err error) {
	c.postErrorMsg(fmt.Sprintf("panic: %s", err.Error()))
	c.log.WithError(err).Panic("🔥")
}

func (c *Client) postErrorMsg(msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	_, _, err := c.repeatableHttpRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/signaling-new/log/error", c.address),
		strings.NewReader(msg),
		map[string]string{"Content-Type": "text/plain"},
	)
	cancel()
	if err != nil {
		c.log.WithError(err).Warn("post error message failed")
	}
}
