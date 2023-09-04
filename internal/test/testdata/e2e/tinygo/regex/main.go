package main

import (
	"regexp"
	"strconv"

	httpwasm "github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

func main() {
	httpwasm.Host.EnableFeatures(api.FeatureBufferResponse)
	httpwasm.HandleRequestFn = handleRequest
	httpwasm.HandleResponseFn = handleResponse
}

const magic = uint32(43)

func handleRequest(api.Request, api.Response) (next bool, reqCtx uint32) {
	return true, magic
}

// var crashingRegex string = `server .{1,50}`
// CRS Rule 932300
var crashingRegex string = `\r\n(?s:.)*?\b(?:(?i:E)(?:HLO [\--\.A-Za-z\x17f\x212a]{1,255}|XPN .{1,64})|HELO [\--\.A-Za-z\x17f\x212a]{1,255}|MAIL FROM:<.{1,64}(?i:@).{1,255}(?i:>)|(?i:R)(?:CPT TO:(?:(?i:<).{1,64}(?i:@).{1,255}(?i:>)|(?i: ))?(?i:<).{1,64}(?i:>)|SET\b)|VRFY .{1,64}(?: <.{1,64}(?i:@).{1,255}(?i:>)|(?i:@).{1,255})|AUTH [\-0-9A-Z_a-z\x17f\x212a]{1,20}(?i: )(?:(?:[\+/-9A-Z_a-z\x17f\x212a]{4})*(?:[\+/-9A-Z_a-z\x17f\x212a]{2}(?i:=)|[\+/-9A-Z_a-z\x17f\x212a]{3}))?(?i:=)|STARTTLS\b|NOOP\b(?:(?i: ).{1,255})?)`

func handleResponse(reqCtx uint32, _ api.Request, resp api.Response, _ bool) {

	regex, err := regexp.Compile(crashingRegex)
	if err != nil {
		resp.Body().WriteString(err.Error())
	} else {
		resp.Body().WriteString(strconv.Itoa(int(reqCtx)))
	}
	if regex.MatchString("dummy no match") {
		resp.SetStatusCode(202)
	}
}
