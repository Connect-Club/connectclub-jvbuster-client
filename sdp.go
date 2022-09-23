package jvbuster

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func insertLine(lines []string, index int, line string) []string {
	if len(lines) == index { // nil or empty slice or after last element
		return append(lines, line)
	}
	lines = append(lines[:index+1], lines[index:]...) // index < len(a)
	lines[index] = line
	return lines
}

func removeLine(lines []string, index int) []string {
	return append(lines[:index], lines[index+1:]...)
}

type NumOfSimulcastLayers uint

//goland:noinspection GoUnusedConst
const (
	TwoSimulcastLayers   NumOfSimulcastLayers = 2
	ThreeSimulcastLayers                      = 3
)

func mungeSdpForSimulcasting(lines []string, numOfSimulcastLayers NumOfSimulcastLayers) []string {
	mLineRegex := regexp.MustCompile("m=(\\w+) *")
	fidLineRegex := regexp.MustCompile("a=ssrc-group:FID (\\d+) (\\d+)")

	video := false
	ssrc := []int64{-1}
	ssrcFid := []int64{-1}
	var cname string
	insertAt := -1
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		mLineMatches := mLineRegex.FindStringSubmatch(line)
		if len(mLineMatches) > 0 {
			medium := mLineMatches[1]
			if medium == "video" {
				if ssrc[0] == -1 {
					video = true
				} else {
					insertAt = i
					break
				}
			} else {
				if ssrc[0] > -1 {
					insertAt = i
					break
				}
			}
			continue
		}
		if !video {
			continue
		}
		fidLineMatches := fidLineRegex.FindStringSubmatch(line)
		if len(fidLineMatches) > 0 {
			ssrc[0], _ = strconv.ParseInt(fidLineMatches[1], 10, 64)
			ssrcFid[0], _ = strconv.ParseInt(fidLineMatches[2], 10, 64)
			lines = removeLine(lines, i)
			i--
			continue
		}
		if ssrc[0] > 0 {
			cnameLineRegex := regexp.MustCompile(fmt.Sprintf("a=ssrc:%v cname:(.+)", ssrc[0]))
			matches := cnameLineRegex.FindStringSubmatch(line)
			if len(matches) > 0 {
				cname = matches[1]
			}
			if strings.HasPrefix(line, fmt.Sprintf("a=ssrc:%v", ssrcFid[0])) {
				lines = removeLine(lines, i)
				i--
				continue
			}
			if strings.HasPrefix(line, fmt.Sprintf("a=ssrc:%v", ssrc[0])) {
				lines = removeLine(lines, i)
				i--
				continue
			}
		}
	}
	if insertAt < 0 {
		insertAt = len(lines) - 1
	}
	for i := 1; i < int(numOfSimulcastLayers); i++ {
		ssrc = append(ssrc, int64(rand.Uint32()))
		ssrcFid = append(ssrcFid, int64(rand.Uint32()))
	}
	for i := range ssrc {
		if len(cname) > 0 {
			lines = insertLine(lines, insertAt, fmt.Sprintf("a=ssrc:%v cname:%v", ssrc[i], cname))
			insertAt++
		}
		//todo: msid, mslabel, label
		// Add the same info for the retransmission SSRC
		if len(cname) > 0 {
			lines = insertLine(lines, insertAt, fmt.Sprintf("a=ssrc:%v cname:%v", ssrcFid[i], cname))
			insertAt++
		}
		//todo: msid, mslabel, label
	}
	for i := range ssrc {
		lines = insertLine(lines, insertAt, fmt.Sprintf("a=ssrc-group:FID %v %v", ssrc[i], ssrcFid[i]))
	}
	simSsrc := fmt.Sprintf("%v", ssrc)
	lines = insertLine(lines, insertAt, fmt.Sprintf("a=ssrc-group:SIM %v", simSsrc[1:len(simSsrc)-1]))
	return lines
}

func insertConfId(lines []string, confId string) []string {
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "m=application") {
			lines = insertLine(lines, i, fmt.Sprintf("a=mid:confId-%v", confId))
			lines = insertLine(lines, i, "m=text 0 UDP 0")
			break
		}
	}
	return lines
}
