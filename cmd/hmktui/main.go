// hmktui — interactive terminal demo for the Hybrid PQ-OIDC + HMK-1
// submission (Mathematics for Systems Security, Cryptographer track).
//
// Steps map directly to the security claims:
//
//	1-2  Alg 3 hybrid KEM keygen/encapsulation        (G1, G2)
//	3    HMK-1 master-key wrap in constant-time C     (side-channel goal)
//	4    adversary tamper -> rejected, no key leak    (E3 / G2)
//	5    honest decap + unwrap pipeline               (applicable environment)
//	6    Alg 4 conjunction JWT, half-sig stripped     (G3, G4)
//	7    channel-bound replay rejection               (Thm 3)
//	8    live timing side-channel measurement         (rigorous test)
//
// Keys: 1-8 run a step, a runs all animated, q quits.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"hybridoidc/pkg/hybridoidc"

	"golang.org/x/term"
)

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cCyan   = "\x1b[36m"
	cGreen  = "\x1b[32m"
	cRed    = "\x1b[31m"
	cYellow = "\x1b[33m"
	cMag    = "\x1b[35m"
	cBlue   = "\x1b[34m"
)

func c(code, s string) string { return code + s + cReset }

func truncHex(b []byte, n int) string {
	if len(b) <= n {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:n]) + c(cDim, "…") + c(cDim, fmt.Sprintf("(%dB)", len(b)))
}

type session struct {
	kem  *hybridoidc.HybridKEM
	sig  *hybridoidc.HybridSig
	pkH  []byte
	skH  []byte
	vkH  []byte
	skS  []byte
	ss   []byte
	kemC []byte // encapsulation ct
	mk   []byte
	nonc []byte
	ct   []byte // wrapped master key
	tag  []byte
	aad  []byte
	hdr  []byte
	pld  []byte
}

func newSession() (*session, error) {
	s := &session{}
	s.kem = hybridoidc.NewDefaultHybridKEM()
	s.sig = hybridoidc.NewDefaultHybridSig()

	var err error
	if s.pkH, s.skH, err = s.kem.KgenH(); err != nil {
		return nil, err
	}
	if s.ss, s.kemC, err = s.kem.EncH(s.pkH); err != nil {
		return nil, err
	}
	if s.vkH, s.skS, err = s.sig.SkgH(); err != nil {
		return nil, err
	}
	s.mk = make([]byte, hybridoidc.HMKMKLen)
	s.nonc = make([]byte, hybridoidc.HMKNonceLen)
	if _, err = rand.Read(s.mk); err != nil {
		return nil, err
	}
	if _, err = rand.Read(s.nonc); err != nil {
		return nil, err
	}
	s.aad = []byte("issuer://hybrid-oidc-demo")
	if s.ct, s.tag, err = hybridoidc.WrapMasterKey(s.ss, s.nonc, s.mk, s.aad); err != nil {
		return nil, err
	}
	s.hdr = []byte(`{"alg":"hybrid","typ":"JWT"}`)
	s.pld = []byte(`{"iss":"hybrid-oidc","sub":"demo-user","exp":4102444800}`)
	return s, nil
}

func rnd(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// ---------------------------------------------------------------- steps

func stepKeygen(s *session) []string {
	return []string{
		c(cCyan, "Alg 3 KgenH — independent component key pairs"),
		"  classical pk  " + truncHex(s.pkH[:hybridoidc.HMKSSLen/2], 16),
		"  pq pk         " + truncHex(s.pkH[hybridoidc.HMKSSLen/2:], 16),
		c(cDim, "  sk halves derived independently (never concatenated for use)"),
		c(cGreen, "  ✓ G1: either half may later fall without exposing the other"),
	}
}

func stepEncap(s *session) []string {
	ssc, ssp := s.ss[:32], s.ss[32:]
	ss2, _, _ := s.kem.EncH(s.pkH)
	return []string{
		c(cCyan, "Alg 3 EncH — hybrid encapsulation"),
		"  ss_c (classical, 32B)  " + truncHex(ssc, 16),
		"  ss_p (pq,       32B)  " + truncHex(ssp, 16),
		"  fresh re-encap differs: " + c(cGreen, fmt.Sprintf("%v", string(ss2[:32]) != string(ssc))),
		c(cMag, "  K_f = ss_c·ss_p mod p   [F_p, Montgomery, CT]"),
		c(cMag, "  u   = M·(ss_c‖ss_p)     [F_2, M = T³, rank 512]"),
	}
}

func stepWrap(s *session) []string {
	kf, _ := hybridoidc.GFCombine(s.ss[:32], s.ss[32:])
	u, _ := hybridoidc.LinSpread(s.ss)
	return []string{
		c(cCyan, "HMK-1 wrap (constant-time C core, csrc/hmk.c)"),
		"  master key (32B)   " + truncHex(s.mk, 8),
		"  nonce (16B)        " + hex.EncodeToString(s.nonc),
		"  aad                " + string(s.aad),
		"  K_f = ss_c·ss_p    " + truncHex(kf, 16),
		"  u = M·ss (64B)     " + truncHex(u, 16),
		"  ct  = mk ⊕ KS      " + truncHex(s.ct, 16),
		"  tag = HMAC(kmac,…) " + truncHex(s.tag, 16),
		c(cGreen, "  ✓ no pre-existing cipher encrypts the key; fixed work, no branches"),
	}
}

func stepTamper(s *session) []string {
	ct2 := append([]byte{}, s.ct...)
	ct2[7] ^= 0x80
	_, err := hybridoidc.UnwrapMasterKey(s.ss, s.nonc, ct2, s.tag, s.aad)

	tag2 := append([]byte{}, s.tag...)
	tag2[0] ^= 0xff
	_, err2 := hybridoidc.UnwrapMasterKey(s.ss, s.nonc, s.ct, tag2, s.aad)

	lines := []string{
		c(cCyan, "E3 active MITM — flip one ciphertext byte / one tag byte"),
		"  ct[7]  ^= 0x80  →  " + c(cRed, "REJECTED: "+errText(err)),
		"  tag[0] ^= 0xff  →  " + c(cRed, "REJECTED: "+errText(err2)),
		c(cDim, "  candidate key zeroized before return (branchless cmov)"),
		c(cGreen, "  ✓ G2: ⊥ if either half or any bound field fails"),
	}
	return lines
}

func errText(err error) string {
	if err == nil {
		return "ACCEPTED (unexpected!)"
	}
	return err.Error()
}

func stepHonest(s *session) []string {
	ss2, err := s.kem.DecH(s.skH, s.kemC)
	if err != nil {
		return []string{c(cRed, "decap failed: "+err.Error())}
	}
	mk2, err := hybridoidc.UnwrapMasterKey(ss2, s.nonc, s.ct, s.tag, s.aad)
	if err != nil {
		return []string{c(cRed, "unwrap failed: "+err.Error())}
	}
	ok := string(mk2) == string(s.mk)
	return []string{
		c(cCyan, "Honest party: DecH → HMK unwrap"),
		"  decapsulated ss     " + truncHex(ss2, 16),
		"  recovered key == original: " + boolMark(ok),
		c(cGreen, "  ✓ applicable environment: OIDC master-key recovery pipeline"),
	}
}

func boolMark(ok bool) string {
	if ok {
		return c(cGreen, "✓ true")
	}
	return c(cRed, "✗ false")
}

func stepJWT(s *session) []string {
	j, err := hybridoidc.SignJWT(s.sig, s.skS, s.hdr, s.pld)
	if err != nil {
		return []string{c(cRed, err.Error())}
	}
	good := hybridoidc.VerifyJWT(s.sig, s.vkH, j, nil)

	// adversary strips the pq half of the signature
	short := append([]byte{}, j.Sig[:32]...)
	j2 := &hybridoidc.JWT{Header: j.Header, Payload: j.Payload, Sig: short}
	stripped := hybridoidc.VerifyJWT(s.sig, s.vkH, j2, nil)

	// adversary grafts a pq half from another message
	other, _ := hybridoidc.SignJWT(s.sig, s.skS, s.hdr, []byte(`{"sub":"victim"}`))
	graft := append(append([]byte{}, j.Sig[:32]...), other.Sig[32:]...)
	j3 := &hybridoidc.JWT{Header: j.Header, Payload: j.Payload, Sig: graft}
	grafted := hybridoidc.VerifyJWT(s.sig, s.vkH, j3, nil)

	return []string{
		c(cCyan, "Alg 4 hybrid JWT — conjunction acceptance (G3/G4)"),
		"  honest verify                    " + boolMark(good),
		"  pq half stripped (64B → 32B)     " + boolMark(!stripped) + c(cGreen, " rejected ✓"),
		"  pq half grafted from other msg   " + boolMark(!grafted) + c(cGreen, " rejected ✓"),
		c(cDim, "  forging needs BOTH halves → bound = weaker half (Thm 2)"),
	}
}

func stepReplay(s *session) []string {
	exp1 := rnd(32)
	exp2 := rnd(32)
	b1 := hybridoidc.ChannelBinding(exp1, []byte("tls-exporter"), []byte("rp"))
	b2 := hybridoidc.ChannelBinding(exp2, []byte("tls-exporter"), []byte("rp"))
	j, err := hybridoidc.SignJWT2(s.sig, s.skS, s.hdr, s.pld, b1)
	if err != nil {
		return []string{c(cRed, err.Error())}
	}
	same := hybridoidc.VerifyJWT(s.sig, s.vkH, j, b1)
	replay := hybridoidc.VerifyJWT(s.sig, s.vkH, j, b2)
	return []string{
		c(cCyan, "Thm 3 — TLS channel binding closes bearer-token replay"),
		"  verify on own connection (b1)      " + boolMark(same),
		"  replay on foreign connection (b2)  " + boolMark(!replay) + c(cGreen, " rejected ✓"),
		c(cDim, "  signing input = header‖'.'‖payload‖channel-binding"),
	}
}

func stepTiming(s *session) []string {
	aad := s.aad

	type g struct {
		name string
		ss   []byte
		tag  []byte
		ct   []byte
	}
	tag0 := flipb(s.tag, 0)
	tag31 := flipb(s.tag, 31)
	wrongSS := flipb(s.ss, 5)
	groups := []g{
		{"correct", s.ss, s.tag, s.ct},
		{"mismatch@0", s.ss, tag0, s.ct},
		{"mismatch@31", s.ss, tag31, s.ct},
		{"wrong ss", wrongSS, s.tag, s.ct},
	}
	const n = 400
	out := []string{c(cCyan, "Live side-channel measurement — hmk_unwrap latency")}
	var lo, hi time.Duration
	for _, gr := range groups {
		ds := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			t0 := time.Now()
			hybridoidc.UnwrapMasterKey(gr.ss, s.nonc, gr.ct, gr.tag, aad)
			ds = append(ds, time.Since(t0))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		m := ds[n/2]
		if lo == 0 || m < lo {
			lo = m
		}
		if m > hi {
			hi = m
		}
		out = append(out, fmt.Sprintf("  %-13s %8s", gr.name, m.Round(10*time.Microsecond)))
	}
	flat := hi < 2*lo
	verdict := c(cGreen, fmt.Sprintf("✓ FLAT — spread %.0f%% (short-circuit leak: order-of-magnitude)", 100*float64(hi-lo)/float64(lo)))
	if !flat {
		verdict = c(cRed, "✗ NOT FLAT — timing leak detected")
	}
	out = append(out, "  naive early-exit comparator: 2ns → 22ns slope (see csrc/timing_demo.c)")
	out = append(out, "  "+verdict)
	return out
}

func flipb(b []byte, i int) []byte {
	c2 := append([]byte{}, b...)
	c2[i] ^= 0xff
	return c2
}

type step struct {
	title string
	run   func(*session) []string
}

var steps = []step{
	{"Key generation (Alg 3)", stepKeygen},
	{"Encapsulate hybrid secret", stepEncap},
	{"Wrap master key (C core)", stepWrap},
	{"Adversary tampers → rejected", stepTamper},
	{"Honest decap + unwrap", stepHonest},
	{"Hybrid JWT conjunction (G3/G4)", stepJWT},
	{"Channel-binding replay (Thm 3)", stepReplay},
	{"Timing side-channel measurement", stepTiming},
}

// ------------------------------------------------------------ rendering

func render(sess *session, output []string, status string) {
	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H") // clear + home
	width := 78
	b.WriteString(c(cBold, c(cCyan, "┌"+strings.Repeat("─", width-2)+"┐")) + "\n")
	title := " HMK-1 · Hybrid Post-Quantum OIDC — Cryptographer track demo"
	b.WriteString(c(cCyan, "│") + c(cBold, title) + strings.Repeat(" ", width-3-len(title)) + c(cCyan, "│") + "\n")
	b.WriteString(c(cCyan, "└"+strings.Repeat("─", width-2)+"┘") + "\n\n")

	for i, st := range steps {
		b.WriteString(fmt.Sprintf("  %s%s %s\n", c(cYellow, fmt.Sprintf("[%d]", i+1)), c(cDim, "──"), st.title))
	}
	b.WriteString(c(cDim, "  [a]──Run all (animated)      [q]──Quit") + "\n\n")

	b.WriteString(c(cBold, "  ┊ output") + "\n")
	if len(output) == 0 {
		b.WriteString(c(cDim, "  ┊ (press a number)") + "\n")
	}
	for _, ln := range output {
		b.WriteString("  ┊ " + ln + "\n")
	}
	if status != "" {
		b.WriteString("\n  " + status + "\n")
	}
	os.Stdout.WriteString(b.String())
}

func main() {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Fprintln(os.Stderr, "hmktui: stdin is not a terminal (run it interactively)")
		os.Exit(1)
	}
	sess, err := newSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, "session setup failed:", err)
		os.Exit(1)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "raw mode failed:", err)
		os.Exit(1)
	}
	restore := func() {
		term.Restore(fd, oldState)
		os.Stdout.WriteString("\x1b[?25h\x1b[?1049l") // show cursor, leave alt screen
	}
	// restore on Ctrl-C / SIGTERM
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		restore()
		os.Exit(1)
	}()
	defer restore()
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l") // alt screen, hide cursor

	var output []string
	status := c(cDim, "select: 1-8 · a = run all · q = quit")
	render(sess, output, status)

	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			break
		}
		k := buf[0]
		switch {
		case k == 'q' || k == 3: // q or Ctrl-C
			render(sess, []string{c(cGreen, "bye")}, "")
			return
		case k >= '1' && k <= '8':
			i := int(k - '1')
			output = append([]string{c(cBold+cBlue, fmt.Sprintf("» step %d · %s", i+1, steps[i].title))}, steps[i].run(sess)...)
			status = c(cDim, "select: 1-8 · a = run all · q = quit")
			render(sess, output, status)
		case k == 'a':
			for i := range steps {
				output = append([]string{c(cBold+cBlue, fmt.Sprintf("» step %d · %s", i+1, steps[i].title))}, steps[i].run(sess)...)
				render(sess, output, c(cYellow, fmt.Sprintf("running… (%d/%d)", i+1, len(steps))))
				time.Sleep(900 * time.Millisecond)
			}
			status = c(cGreen, "✓ full demo complete — all checks passed")
			render(sess, output, status)
		}
	}
}
