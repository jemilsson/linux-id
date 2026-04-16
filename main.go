package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"math/big"
	"sync"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/matejsmycka/linux-id/attestation" // used for CTAP1 registerSite
	"github.com/matejsmycka/linux-id/ctap2"
	"github.com/matejsmycka/linux-id/fidoauth"
	"github.com/matejsmycka/linux-id/fidohid"
	"github.com/matejsmycka/linux-id/fprintd"
	"github.com/matejsmycka/linux-id/memory"
	"github.com/matejsmycka/linux-id/pinentry"
	"github.com/matejsmycka/linux-id/powerled"
	"github.com/matejsmycka/linux-id/sitesignatures"
	"github.com/matejsmycka/linux-id/statuscode"
	"github.com/matejsmycka/linux-id/tpm"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var auth = flag.String("auth", "pinentry", "pinentry|fprintd — pinentry confirms presence (UP only); fprintd verifies identity via fingerprint (UP+UV)")
var deviceName = flag.String("name", "linux-id", "UHID device name (use distinct names when running multiple instances)")
var configPath = flag.String("config", "", "path to config.json (default: ~/.config/linux-id/config.json)")

// ctap2Enc is the CTAP2 Canonical CBOR encoder. Per CTAP §6, all CTAP2
// messages must use canonical encoding (sorted keys, shortest-form integers,
// definite-length items). The default cbor.Marshal does not enforce this and
// emits map keys in Go iteration order, which some clients reject.
var ctap2Enc cbor.EncMode = func() cbor.EncMode {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

// tokenResponder is the subset of *fidohid.SoftToken that the request handlers
// need to write replies. It exists so handlers can be unit-tested with a fake.
type tokenResponder interface {
	WriteResponse(ctx context.Context, evt fidohid.AuthEvent, data []byte, status uint16) error
	WriteCtap2Response(ctx context.Context, evt fidohid.AuthEvent, status byte, data []byte) error
	SendKeepalive(evt fidohid.AuthEvent, status byte) error
}

func main() {
	flag.Parse()
	s := newServer()
	s.run()
}

// minVerifyDuration prevents tight retry loops when the verifier fails
// instantly (e.g. fingerprint reader disconnected). If verification fails
// faster than this, the handler waits before responding so the client
// cannot retry at full speed.
const minVerifyDuration = 2 * time.Second

type VerifyFailureReason int

const (
	ReasonUnspecified VerifyFailureReason = iota
	ReasonNoMatch
)

type VerifyResult struct {
	OK     bool
	Reason VerifyFailureReason
	Error  error
}

func statusForFailure(r VerifyResult) byte {
	if r.Reason == ReasonNoMatch {
		return ctap2.StatusUVInvalid
	}
	return ctap2.StatusOperationDenied
}

// UserVerifier abstracts over user confirmation methods for CTAP2.
// pinentry provides User Presence (UP); fprintd provides User Verification (UV).
type UserVerifier interface {
	// VerifyUser starts verification and returns a result channel.
	VerifyUser(prompt string) (<-chan VerifyResult, error)
	// PerformsUV returns true only when the verifier actually identifies the user
	// (e.g. fingerprint). Used to set the UV flag in authenticatorData honestly.
	PerformsUV() bool
}

type pinentryVerifier struct{ pe *pinentry.Pinentry }

func (v *pinentryVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	ch, err := v.pe.ConfirmGeneric(prompt)
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() { r := <-ch; out <- VerifyResult{OK: r.OK, Error: r.Error} }()
	return out, nil
}

func (v *pinentryVerifier) PerformsUV() bool { return false }

type fprintdVerifier struct{ fp *fprintd.Fprintd }

func (v *fprintdVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	ch, err := v.fp.VerifyPresence()
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() {
		r := <-ch
		result := VerifyResult{OK: r.OK, Error: r.Error}
		if !r.OK && errors.Is(r.Error, fprintd.ErrNoMatch) {
			result.Reason = ReasonNoMatch
		}
		out <- result
	}()
	return out, nil
}

func (v *fprintdVerifier) PerformsUV() bool { return true }

const uvCacheTTL = 5 * time.Second

type cachingVerifier struct {
	inner  UserVerifier
	ttl    time.Duration
	now    func() time.Time
	mu     sync.Mutex
	lastOK time.Time
}

func newCachingVerifier(inner UserVerifier) *cachingVerifier {
	return newCachingVerifierWithTTL(inner, uvCacheTTL)
}

func newCachingVerifierWithTTL(inner UserVerifier, ttl time.Duration) *cachingVerifier {
	return &cachingVerifier{inner: inner, ttl: ttl, now: time.Now}
}

func (v *cachingVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	v.mu.Lock()
	if !v.lastOK.IsZero() && v.now().Sub(v.lastOK) < v.ttl {
		v.mu.Unlock()
		log.Print("verifier: UV cache hit, skipping prompt")
		ch := make(chan VerifyResult, 1)
		ch <- VerifyResult{OK: true}
		return ch, nil
	}
	v.mu.Unlock()

	innerCh, err := v.inner.VerifyUser(prompt)
	if err != nil {
		return nil, err
	}
	out := make(chan VerifyResult, 1)
	go func() {
		r := <-innerCh
		if r.OK {
			v.mu.Lock()
			v.lastOK = v.now()
			v.mu.Unlock()
		}
		out <- r
	}()
	return out, nil
}

func (v *cachingVerifier) PerformsUV() bool { return v.inner.PerformsUV() }

// autoApproveVerifier always grants verification without prompting.
// Used when global auto_approve_all is set for headless/agent operation.
type autoApproveVerifier struct{}

func (v *autoApproveVerifier) VerifyUser(prompt string) (<-chan VerifyResult, error) {
	ch := make(chan VerifyResult, 1)
	ch <- VerifyResult{OK: true}
	return ch, nil
}

func (v *autoApproveVerifier) PerformsUV() bool { return false }

// pinentryClient is the subset of *pinentry.Pinentry that the U2F handlers
// use. Exists so handleRegister/handleAuthenticate can be unit-tested with a fake.
type pinentryClient interface {
	ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan pinentry.Result, error)
}

type server struct {
	pe       pinentryClient // CTAP1/U2F — browser-retry dedup via challenge params
	verifier UserVerifier   // CTAP2 — configured via --auth flag
	signer   Signer
	cs       *ctap2.CredStore
	known    *ctap2.KnownHandles
	cfg      Config

	// ECDH key pair for hmac-secret / clientPIN key agreement (pinProtocol 1).
	// Generated once at startup, discarded on power-off.
	ecdhPriv *ecdsa.PrivateKey

	led *powerled.Blinker
}

type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	UnsealCredRandom(keyHandle, applicationParam []byte) ([]byte, error)
	Counter() uint32
}

func newServer() *server {
	pe := pinentry.New()
	cfg := loadConfig(*configPath)
	s := server{
		pe:    pe,
		cs:    ctap2.NewCredStore(),
		known: ctap2.NewKnownHandles(),
		cfg:   cfg,
		led:   powerled.New(),
	}

	if cfg.AutoApproveAll {
		log.Print("config: auto_approve_all enabled, all verification prompts will be skipped")
		s.verifier = &autoApproveVerifier{}
	} else {
		var inner UserVerifier
		switch *auth {
		case "fprintd":
			inner = &fprintdVerifier{fp: fprintd.New()}
		default:
			inner = &pinentryVerifier{pe: pe}
		}
		if ttl := cfg.UVCacheTTL(); ttl > 0 {
			s.verifier = newCachingVerifierWithTTL(inner, ttl)
		} else {
			log.Print("config: uv_cache_ttl_seconds=0, every sign will prompt fresh")
			s.verifier = inner
		}
	}

	// Generate ECDH key pair for hmac-secret / clientPIN key agreement.
	ecdhKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate ECDH key: %s", err)
	}
	s.ecdhPriv = ecdhKey

	if *backend == "tpm" {
		signer, err := tpm.New(*device)
		if err != nil {
			panic(err)
		}
		s.signer = signer
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			panic(err)
		}
		s.signer = signer
	}
	return &s
}

func (s *server) run() {
	log.Printf("Starting linux-id server (name=%s, auth=%s)", *deviceName, *auth)

	ctx := context.Background()

	if *auth == "pinentry" && pinentry.FindPinentryGUIPath() == "" {
		log.Printf("warning: no gui pinentry binary detected in PATH. linux-id may not work correctly without a gui based pinentry")
	}

	token, err := fidohid.New(ctx, *deviceName)
	if err != nil {
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		// Route CTAP2 (CmdCbor) events before accessing evt.Req.
		if evt.RawCbor != nil {
			s.handleCtap2(ctx, token, evt)
			continue
		}

		if evt.Error != nil {
			log.Printf("got token error: %s", evt.Error)
			continue
		}

		req := evt.Req

		if req.Command == fidoauth.CmdAuthenticate {
			log.Printf("got AuthenticateCmd site=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam))
			s.handleAuthenticate(ctx, token, evt)
		} else if req.Command == fidoauth.CmdRegister {
			log.Printf("got RegisterCmd site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
			s.handleRegister(ctx, token, evt)
		} else if req.Command == fidoauth.CmdVersion {
			log.Print("got VersionCmd")
			s.handleVersion(ctx, token, evt)
		} else {
			log.Printf("unsupported request type: 0x%02x\n", req.Command)
			// send a not supported error for any commands that we don't understand.
			// Browsers depend on this to detect what features the token supports
			// (i.e. the u2f backwards compatibility)
			token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
		}
	}
}

func (s *server) handleVersion(parentCtx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Printf("Sending version 'U2F_V2' for CTAP1/U2F compatibility")
	if err := token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError); err != nil {
		log.Printf("write version response err: %s", err)
		return
	}
}

func (s *server) handleAuthenticate(parentCtx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]

	dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))

	_, err := s.signer.SignASN1(keyHandle, appParam, dummySig[:])
	if err != nil {
		log.Printf("invalid key: %s (key handle size: %d)", err, len(keyHandle))

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		log.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		// check if the provided key is known by the token
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == fidoauth.CtrlEnforeUserPresenceAndSign {

		verifyStart := time.Now()
		resultCh, err := s.verifier.VerifyUser("FIDO U2F Auth")

		if err != nil {
			log.Printf("U2F verifier err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 35*time.Second)
		defer cancel()
		s.led.Start(500 * time.Millisecond)

		select {
		case result := <-resultCh:
			s.led.Stop()
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					log.Printf("U2F verifier result err: %s", result.Error)
				}
				if wait := minVerifyDuration - time.Since(verifyStart); wait > 0 {
					time.Sleep(wait)
				}
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					log.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			s.led.Stop()
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	s.led.Start(100 * time.Millisecond)
	defer s.led.Stop()

	signCounter := s.signer.Counter()

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sig, err := s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()
	req := evt.Req

	if s.cfg.AutoApproveAll {
		log.Print("U2F Register: auto-approving (auto_approve_all)")
		s.registerSite(parentCtx, token, evt)
		return
	}

	pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Register", req.Register.ChallengeParam, req.Register.ApplicationParam)

	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	s.led.Start(500 * time.Millisecond)
	select {
	case result := <-pinResultCh:
		s.led.Stop()
		if !result.OK {
			if result.Error != nil {
				log.Printf("Got pinentry result err: %s", result.Error)
			}

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				log.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		s.registerSite(parentCtx, token, evt)
	case <-ctx.Done():
		s.led.Stop()
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	s.led.Start(100 * time.Millisecond)
	defer s.led.Stop()

	req := evt.Req

	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		log.Printf("RegisteKey err: %s", err)
		return
	}

	if len(keyHandle) > 255 {
		log.Printf("Error: keyHandle too large: %d, max=255", len(keyHandle))
		return
	}

	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sum := sigHash.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		log.Fatalf("attestation sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}
}

// handleCtap2 dispatches incoming CTAP2 (CmdCbor) events.
func (s *server) handleCtap2(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	if len(evt.RawCbor) == 0 {
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	cmd, payload := evt.RawCbor[0], evt.RawCbor[1:]
	switch cmd {
	case ctap2.CmdGetInfo:
		s.handleGetInfo(ctx, token, evt)
	case ctap2.CmdMakeCredential:
		s.handleMakeCredential(ctx, token, evt, payload)
	case ctap2.CmdGetAssertion:
		s.handleGetAssertion(ctx, token, evt, payload)
	case ctap2.CmdClientPIN:
		s.handleClientPIN(ctx, token, evt, payload)
	default:
		log.Printf("unsupported CTAP2 cmd 0x%02x", cmd)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusNotAllowed, nil)
	}
}

// handleGetInfo returns CTAP2 authenticator capabilities.
// The UV option is honest: true only when using fprintd (actual identity verification).
func (s *server) handleGetInfo(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent) {
	log.Print("got Ctap2Cmd GetInfo")

	options := map[string]bool{
		"rk":        true,
		"up":        true,
		"uv":        s.verifier.PerformsUV(),
		"clientPin": false,
	}

	response := map[int]interface{}{
		1: []string{"FIDO_2_0"},
		2: []string{"hmac-secret"},      // extensions
		3: make([]byte, 16),             // AAGUID: 16 zero bytes (uncertified)
		4: options,
		5: 1200,                         // maxMsgSize
		6: []int{1},                     // pinUvAuthProtocols
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("GetInfo marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// handleMakeCredential implements CTAP2 authenticatorMakeCredential (passkey registration).
func (s *server) handleMakeCredential(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	log.Print("got Ctap2Cmd MakeCredential")

	var req ctap2.MakeCredentialRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("MakeCredential decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	if len(req.ClientDataHash) != 32 {
		log.Printf("MakeCredential: invalid clientDataHash length %d", len(req.ClientDataHash))
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	// Verify at least one supported algorithm (ES256 = -7).
	hasES256 := false
	for _, p := range req.PubKeyCredParams {
		if p.Alg == -7 {
			hasES256 = true
			break
		}
	}
	if !hasES256 {
		log.Print("MakeCredential: no ES256 in pubKeyCredParams")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusUnsupportedAlg, nil)
		return
	}

	// If the RP requests uv=true but our verifier only provides user presence, reject.
	if req.Options != nil && req.Options.UV && !s.verifier.PerformsUV() {
		log.Print("MakeCredential: uv=true requested but verifier cannot verify identity")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	rpIdHash := sha256.Sum256([]byte(req.RP.ID))

	// Per spec §6.1: user presence MUST be obtained before checking excludeList.
	// Checking after UP prevents timing attacks that reveal credential existence
	// without user consent.
	if s.cfg.AutoApprove(req.RP.ID) {
		log.Printf("MakeCredential: auto-approving for rp=%s", req.RP.ID)
	} else {
		verifyStart := time.Now()
		resultCh, err := s.verifier.VerifyUser("FIDO2 Register: " + req.RP.ID)
		if err != nil {
			log.Printf("MakeCredential verifier err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		childCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		s.led.Start(500 * time.Millisecond)
		keepaliveDone := make(chan struct{})
		keepaliveStopped := make(chan struct{})
		go func() {
			defer close(keepaliveStopped)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					token.SendKeepalive(evt, 0x02)
				case <-keepaliveDone:
					return
				}
			}
		}()
		select {
		case result := <-resultCh:
			close(keepaliveDone)
			<-keepaliveStopped
			s.led.Stop()
			if !result.OK {
				if result.Error != nil {
					log.Printf("MakeCredential verifier result err: %s", result.Error)
				}
				if wait := minVerifyDuration - time.Since(verifyStart); wait > 0 {
					time.Sleep(wait)
				}
				token.WriteCtap2Response(ctx, evt, statusForFailure(result), nil)
				return
			}
		case <-childCtx.Done():
			close(keepaliveDone)
			<-keepaliveStopped
			s.led.Stop()
			token.WriteCtap2Response(ctx, evt, ctap2.StatusUserActionTimeout, nil)
			return
		}
	}

	s.led.Start(100 * time.Millisecond)
	defer s.led.Stop()

	// Check excludeList after UP: if a credential already exists for this RP, reject.
	if len(req.ExcludeList) > 0 {
		dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
		for _, cred := range req.ExcludeList {
			if _, err := s.signer.SignASN1(cred.ID, rpIdHash[:], dummySig[:]); err == nil {
				log.Printf("MakeCredential: credential already exists for rp=%s", req.RP.ID)
				token.WriteCtap2Response(ctx, evt, ctap2.StatusCredentialExcluded, nil)
				return
			}
		}
	}

	keyHandle, x, y, err := s.signer.RegisterKey(rpIdHash[:])
	if err != nil {
		log.Printf("MakeCredential RegisterKey err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	// Build COSE EC public key (integer map keys per RFC 8152).
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)
	coseKey := map[int]interface{}{
		1:  2,      // kty: EC2
		3:  -7,     // alg: ES256
		-1: 1,      // crv: P-256
		-2: xBytes, // x
		-3: yBytes, // y
	}
	coseKeyBytes, err := ctap2Enc.Marshal(coseKey)
	if err != nil {
		log.Printf("MakeCredential coseKey marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	// authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16) | credIdLen(2) | credId | coseKey [| extensions]
	// UV flag is set only when the verifier actually verified the user's identity.
	authFlags := ctap2.AuthFlagUP | ctap2.AuthFlagAT
	if s.verifier.PerformsUV() {
		authFlags |= ctap2.AuthFlagUV
	}
	if s.cfg.BackupEligible(req.RP.ID) {
		authFlags |= ctap2.AuthFlagBE
	}

	// Process hmac-secret extension in MakeCredential: confirm support.
	hmacSecretRequested := false
	if req.Extensions != nil {
		if v, ok := req.Extensions["hmac-secret"]; ok {
			if b, ok := v.(bool); ok && b {
				hmacSecretRequested = true
			}
		}
	}
	if hmacSecretRequested {
		authFlags |= ctap2.AuthFlagED
	}

	var authDataBuf bytes.Buffer
	authDataBuf.Write(rpIdHash[:])
	authDataBuf.WriteByte(authFlags)
	binary.Write(&authDataBuf, binary.BigEndian, s.signer.Counter())
	authDataBuf.Write(make([]byte, 16)) // AAGUID: 16 zero bytes
	binary.Write(&authDataBuf, binary.BigEndian, uint16(len(keyHandle)))
	authDataBuf.Write(keyHandle)
	authDataBuf.Write(coseKeyBytes)

	if hmacSecretRequested {
		extData := map[string]bool{"hmac-secret": true}
		extBytes, err := ctap2Enc.Marshal(extData)
		if err != nil {
			log.Printf("MakeCredential extension marshal err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		authDataBuf.Write(extBytes)
	}
	authDataBytes := authDataBuf.Bytes()

	// Use "none" attestation: we have no hardware cert chain to present,
	// and returning the shared SoftU2F cert causes servers to reject the credential.
	response := map[int]interface{}{
		1: "none",
		2: authDataBytes,
		3: map[interface{}]interface{}{},
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("MakeCredential response marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	// Persist as resident credential if rk option is set.
	if req.Options != nil && req.Options.RK {
		err := s.cs.Save(ctap2.StoredCredential{
			CredID:      keyHandle,
			RPIDHash:    rpIdHash[:],
			RPID:        req.RP.ID,
			RPName:      req.RP.Name,
			UserID:      req.User.ID,
			UserName:    req.User.Name,
			DisplayName: req.User.DisplayName,
		})
		if err != nil {
			log.Printf("MakeCredential credstore save err: %s", err)
		}
	}

	log.Printf("MakeCredential ok: rp=%s keyHandle=%d bytes", req.RP.ID, len(keyHandle))
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// handleGetAssertion implements CTAP2 authenticatorGetAssertion (passkey authentication).
func (s *server) handleGetAssertion(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	log.Print("got Ctap2Cmd GetAssertion")

	var req ctap2.GetAssertionRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("GetAssertion decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	if len(req.ClientDataHash) != 32 {
		log.Printf("GetAssertion: invalid clientDataHash length %d", len(req.ClientDataHash))
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	// If the RP requests uv=true but our verifier only provides user presence, reject.
	if req.Options != nil && req.Options.UV && !s.verifier.PerformsUV() {
		log.Print("GetAssertion: uv=true requested but verifier cannot verify identity")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidOption, nil)
		return
	}

	rpIdHash := sha256.Sum256([]byte(req.RPID))

	// Resolve credential: allowList takes priority over resident credentials.
	var keyHandle []byte
	var storedCred *ctap2.StoredCredential
	if len(req.AllowList) > 0 {
		// Pick one credential from the allowList. Strategy:
		//   1. Exactly one entry: use it directly; the real sign catches
		//      malformed or foreign handles after user verification.
		//   2. Multiple entries: prefer a handle we have previously signed
		//      with (cached in known-handles.json). Otherwise fall back to
		//      a dummy-sign probe to find which handle actually belongs to
		//      this TPM, avoiding a wasted fingerprint scan on a handle
		//      that would fail the real sign.
		if len(req.AllowList) == 1 {
			keyHandle = req.AllowList[0].ID
		} else {
			for _, cred := range req.AllowList {
				if s.known.Contains(cred.ID) {
					keyHandle = cred.ID
					break
				}
			}
			if keyHandle == nil {
				dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
				for _, cred := range req.AllowList {
					if _, err := s.signer.SignASN1(cred.ID, rpIdHash[:], dummySig[:]); err == nil {
						keyHandle = cred.ID
						break
					}
				}
				if keyHandle == nil {
					log.Printf("GetAssertion: no valid key handle in allowList for rp=%s", req.RPID)
					token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
					return
				}
			}
		}
	} else {
		creds, err := s.cs.FindByRPID(rpIdHash[:])
		if err != nil {
			log.Printf("GetAssertion credstore err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		if len(creds) == 0 {
			log.Printf("GetAssertion: no credentials for rp=%s", req.RPID)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusNoCredentials, nil)
			return
		}
		storedCred = &creds[0]
		keyHandle = storedCred.CredID
	}

	upRequired := req.Options == nil || req.Options.UP == nil || *req.Options.UP
	if upRequired && s.cfg.AutoApprove(req.RPID) {
		log.Printf("GetAssertion: auto-approving for rp=%s", req.RPID)
	} else if upRequired {
		verifyStart := time.Now()
		resultCh, err := s.verifier.VerifyUser("FIDO2 Authenticate: " + req.RPID)
		if err != nil {
			log.Printf("GetAssertion verifier err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		childCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		s.led.Start(500 * time.Millisecond)
		keepaliveDone := make(chan struct{})
		keepaliveStopped := make(chan struct{})
		go func() {
			defer close(keepaliveStopped)
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					token.SendKeepalive(evt, 0x02)
				case <-keepaliveDone:
					return
				}
			}
		}()
		select {
		case result := <-resultCh:
			close(keepaliveDone)
			<-keepaliveStopped
			s.led.Stop()
			if !result.OK {
				if result.Error != nil {
					log.Printf("GetAssertion verifier result err: %s", result.Error)
				}
				if wait := minVerifyDuration - time.Since(verifyStart); wait > 0 {
					time.Sleep(wait)
				}
				token.WriteCtap2Response(ctx, evt, statusForFailure(result), nil)
				return
			}
		case <-childCtx.Done():
			close(keepaliveDone)
			<-keepaliveStopped
			s.led.Stop()
			token.WriteCtap2Response(ctx, evt, ctap2.StatusUserActionTimeout, nil)
			return
		}
	} else {
		log.Printf("GetAssertion: up=false probe, skipping verification for rp=%s", req.RPID)
	}

	// up=false probes are silent credential-existence checks; don't blink
	// the LED for them, it's confusing to see a flash before the real
	// user-presence prompt.
	if upRequired {
		s.led.Start(100 * time.Millisecond)
		defer s.led.Stop()
	}

	var authFlags byte
	if upRequired {
		authFlags = ctap2.AuthFlagUP
		if s.verifier.PerformsUV() {
			authFlags |= ctap2.AuthFlagUV
		}
		if s.cfg.BackupEligible(req.RPID) {
			authFlags |= ctap2.AuthFlagBE
		}
	}

	// Process hmac-secret extension in GetAssertion.
	var hmacSecretOutput []byte
	if req.Extensions != nil {
		if extRaw, ok := req.Extensions["hmac-secret"]; ok {
			output, err := s.processHmacSecret(extRaw, keyHandle, rpIdHash[:])
			if err != nil {
				log.Printf("GetAssertion hmac-secret err: %s", err)
				token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
				return
			}
			hmacSecretOutput = output
			authFlags |= ctap2.AuthFlagED
		}
	}

	var authDataBuf bytes.Buffer
	authDataBuf.Write(rpIdHash[:])
	authDataBuf.WriteByte(authFlags)
	binary.Write(&authDataBuf, binary.BigEndian, s.signer.Counter())

	if hmacSecretOutput != nil {
		extData := map[string][]byte{"hmac-secret": hmacSecretOutput}
		extBytes, err := ctap2Enc.Marshal(extData)
		if err != nil {
			log.Printf("GetAssertion extension marshal err: %s", err)
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		authDataBuf.Write(extBytes)
	}
	authDataBytes := authDataBuf.Bytes()

	// Sign sha256(authData || clientDataHash) per WebAuthn §7.2.
	toSign := make([]byte, len(authDataBytes)+len(req.ClientDataHash))
	copy(toSign, authDataBytes)
	copy(toSign[len(authDataBytes):], req.ClientDataHash)
	digest := sha256.Sum256(toSign)

	sig, err := s.signer.SignASN1(keyHandle, rpIdHash[:], digest[:])
	if err != nil {
		log.Printf("GetAssertion sign err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}
	s.known.Add(keyHandle)

	response := map[int]interface{}{
		1: map[string]interface{}{"type": "public-key", "id": keyHandle},
		2: authDataBytes,
		3: sig,
	}
	if storedCred != nil {
		response[4] = map[string]interface{}{
			"id":          storedCred.UserID,
			"name":        storedCred.UserName,
			"displayName": storedCred.DisplayName,
		}
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("GetAssertion response marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}

	log.Printf("GetAssertion ok: rp=%s", req.RPID)
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// handleClientPIN implements authenticatorClientPIN (CTAP2 0x06).
// Only getKeyAgreement (subCommand 0x02) is supported, for hmac-secret.
func (s *server) handleClientPIN(ctx context.Context, token tokenResponder, evt fidohid.AuthEvent, payload []byte) {
	log.Print("got Ctap2Cmd ClientPIN")

	var req ctap2.ClientPINRequest
	if err := cbor.Unmarshal(payload, &req); err != nil {
		log.Printf("ClientPIN decode err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusInvalidCbor, nil)
		return
	}

	switch req.SubCommand {
	case ctap2.ClientPINGetRetries:
		// No PIN is set; return max retries to indicate healthy state.
		resp := map[int]interface{}{3: 8} // retries
		encoded, err := ctap2Enc.Marshal(resp)
		if err != nil {
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		log.Print("ClientPIN: returning PIN retries")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
		return
	case ctap2.ClientPINGetUVRetries:
		resp := map[int]interface{}{5: 8} // uvRetries
		encoded, err := ctap2Enc.Marshal(resp)
		if err != nil {
			token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
			return
		}
		log.Print("ClientPIN: returning UV retries")
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
		return
	case ctap2.ClientPINGetKeyAgreement:
		// handled below
	default:
		log.Printf("ClientPIN: unsupported subCommand %d", req.SubCommand)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusNotAllowed, nil)
		return
	}

	// Return the authenticator's ECDH public key in COSE_Key format.
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	s.ecdhPriv.PublicKey.X.FillBytes(xBytes)
	s.ecdhPriv.PublicKey.Y.FillBytes(yBytes)

	coseKey := map[int]interface{}{
		1:  2,      // kty: EC2
		3:  -25,    // alg: ECDH-ES+HKDF-256 (per CTAP2 spec)
		-1: 1,      // crv: P-256
		-2: xBytes, // x
		-3: yBytes, // y
	}

	response := map[int]interface{}{
		1: coseKey, // keyAgreement
	}
	encoded, err := ctap2Enc.Marshal(response)
	if err != nil {
		log.Printf("ClientPIN marshal err: %s", err)
		token.WriteCtap2Response(ctx, evt, ctap2.StatusOperationDenied, nil)
		return
	}
	log.Print("ClientPIN: returning key agreement")
	token.WriteCtap2Response(ctx, evt, ctap2.StatusOK, encoded)
}

// processHmacSecret handles the hmac-secret extension during GetAssertion.
// It performs ECDH key agreement, verifies saltAuth, decrypts salts,
// computes HMAC-SHA-256(CredRandom, salt), and returns the encrypted output.
func (s *server) processHmacSecret(extRaw interface{}, keyHandle, rpIdHash []byte) ([]byte, error) {
	// The extension value is a CBOR map: {1: keyAgreement, 2: saltEnc, 3: saltAuth}
	// Due to CBOR decoding, it arrives as map[interface{}]interface{}.
	extMap, ok := extRaw.(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("hmac-secret: extension value is not a map")
	}

	// Extract platform's COSE key (keyAgreement, key 1).
	keyAgreementRaw, ok := extMap[uint64(1)]
	if !ok {
		return nil, errors.New("hmac-secret: missing keyAgreement (key 1)")
	}
	platformKey, ok := keyAgreementRaw.(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("hmac-secret: keyAgreement is not a map")
	}

	// Parse platform's P-256 public key from COSE format.
	platformX, ok := coseGetBytes(platformKey, int64(-2))
	if !ok || len(platformX) != 32 {
		return nil, errors.New("hmac-secret: invalid platform key x coordinate")
	}
	platformY, ok := coseGetBytes(platformKey, int64(-3))
	if !ok || len(platformY) != 32 {
		return nil, errors.New("hmac-secret: invalid platform key y coordinate")
	}

	// Verify the point is on the curve.
	curve := elliptic.P256()
	pX := new(big.Int).SetBytes(platformX)
	pY := new(big.Int).SetBytes(platformY)
	if !curve.IsOnCurve(pX, pY) {
		return nil, errors.New("hmac-secret: platform key not on P-256 curve")
	}

	// ECDH: shared point = platformPub * authenticatorPriv
	sharedX, _ := curve.ScalarMult(pX, pY, s.ecdhPriv.D.Bytes())
	// pinProtocol 1: sharedSecret = SHA-256(sharedPoint.x)
	xBytes := make([]byte, 32)
	sharedX.FillBytes(xBytes)
	sharedSecret := sha256.Sum256(xBytes)

	// Extract saltEnc (key 2) and saltAuth (key 3).
	saltEnc, ok := coseGetBytes(extMap, uint64(2))
	if !ok {
		return nil, errors.New("hmac-secret: missing saltEnc (key 2)")
	}
	if len(saltEnc) != 32 && len(saltEnc) != 64 {
		return nil, errors.New("hmac-secret: saltEnc must be 32 or 64 bytes")
	}
	saltAuth, ok := coseGetBytes(extMap, uint64(3))
	if !ok {
		return nil, errors.New("hmac-secret: missing saltAuth (key 3)")
	}

	// Verify saltAuth = left(HMAC-SHA-256(sharedSecret, saltEnc), 16).
	mac := hmac.New(sha256.New, sharedSecret[:])
	mac.Write(saltEnc)
	expectedAuth := mac.Sum(nil)[:16]
	if !hmac.Equal(saltAuth, expectedAuth) {
		return nil, errors.New("hmac-secret: saltAuth verification failed")
	}

	// Decrypt salts: AES-256-CBC(sharedSecret, IV=zeros, saltEnc), no padding.
	block, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	decrypter := cipher.NewCBCDecrypter(block, iv)
	salts := make([]byte, len(saltEnc))
	decrypter.CryptBlocks(salts, saltEnc)

	// Get CredRandom from signer (TPM-sealed or derived).
	credRandom, err := s.signer.UnsealCredRandom(keyHandle, rpIdHash)
	if err != nil {
		return nil, err
	}

	// Compute HMAC-SHA-256(CredRandom, salt1) [|| HMAC-SHA-256(CredRandom, salt2)].
	h1 := hmac.New(sha256.New, credRandom)
	h1.Write(salts[:32])
	output := h1.Sum(nil)

	if len(salts) == 64 {
		h2 := hmac.New(sha256.New, credRandom)
		h2.Write(salts[32:64])
		output = append(output, h2.Sum(nil)...)
	}

	// Encrypt output: AES-256-CBC(sharedSecret, IV=zeros, output), no padding.
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(output))
	encrypter.CryptBlocks(encrypted, output)

	return encrypted, nil
}

// coseGetBytes extracts a byte slice from a CBOR map by key.
// The key can be any type the CBOR decoder produces (int64, uint64, etc).
func coseGetBytes(m map[interface{}]interface{}, key interface{}) ([]byte, bool) {
	if v, ok := m[key]; ok {
		if b, ok := v.([]byte); ok {
			return b, true
		}
	}
	return nil, false
}
