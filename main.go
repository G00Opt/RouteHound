// RouteHound — a forced-browsing scanner that replays URLs from a Burp Suite
// XML export without authentication, then flags responses whose status (and,
// optionally, length) still match the authenticated capture.
//
// Author:  NiTr0Rc
// Version: 1.0.0
package main

import (
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Tool metadata
// ---------------------------------------------------------------------------

const (
	toolName    = "RouteHound"
	toolAuthor  = "NiTr0Rc"
	toolVersion = "1.0.0"
	toolTagline = "Forced-browsing scanner for Burp Suite exports"
)

// ---------------------------------------------------------------------------
// ANSI styling
// ---------------------------------------------------------------------------

const (
	cReset      = "\x1b[0m"
	cDim        = "\x1b[2m"
	cRed        = "\x1b[31m"
	cGreen      = "\x1b[32m"
	cYellow     = "\x1b[33m"
	cCyan       = "\x1b[36m"
	cBoldCyan   = "\x1b[1;36m"
	cBoldGreen  = "\x1b[1;32m"
	cBoldRed    = "\x1b[1;31m"
	cBoldYellow = "\x1b[1;33m"
)

var colorOn = true // set from -no-color flag

func paint(code, s string) string {
	if !colorOn {
		return s
	}
	return code + s + cReset
}

func logInfo(format string, args ...any) {
	fmt.Fprintf(os.Stderr, paint(cCyan, "[*]")+" "+format+"\n", args...)
}
func logConfig(format string, args ...any) {
	fmt.Fprintf(os.Stderr, paint(cGreen, "[+]")+" "+format+"\n", args...)
}
func logProgress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, paint(cYellow, "[>]")+" "+format+"\n", args...)
}
func logDone(format string, args ...any) {
	fmt.Fprintf(os.Stderr, paint(cBoldGreen, "[✓]")+" "+format+"\n", args...)
}
func logError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, paint(cBoldRed, "[!]")+" "+format+"\n", args...)
}
func logWarn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, paint(cBoldYellow, "[~]")+" "+format+"\n", args...)
}

func banner() string {
	art := "" +
		"   ____             _       _   _                       _\n" +
		"  |  _ \\ ___  _   _| |_ ___| | | | ___  _   _ _ __   __| |\n" +
		"  | |_) / _ \\| | | | __/ _ \\ |_| |/ _ \\| | | | '_ \\ / _` |\n" +
		"  |  _ < (_) | |_| | ||  __/  _  | (_) | |_| | | | | (_| |\n" +
		"  |_| \\_\\___/ \\__,_|\\__\\___|_| |_|\\___/ \\__,_|_| |_|\\__,_|\n"
	tag := fmt.Sprintf("   %s  v%s  —  %s\n", toolName, toolVersion, toolTagline)
	author := fmt.Sprintf("   Author: %s\n", toolAuthor)
	return paint(cBoldCyan, art) + paint(cYellow, tag) + paint(cDim, author)
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

type BurpItem struct {
	XMLName        xml.Name `xml:"item"`
	URL            string   `xml:"url"`
	Method         string   `xml:"method"`
	Status         string   `xml:"status"`
	ResponseLength string   `xml:"responselength"`
}

type job struct {
	index int
	item  BurpItem
}

type Result struct {
	SNo          int
	URL          string
	Method       string
	BurpStatus   string
	BurpLength   string
	UnauthStatus string
	UnauthLength string
	MatchStatus  string
	MatchLength  string
	Error        string
}

type filters struct {
	scopes      []string
	includeExts []string
	excludeExts []string
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	inputPath := flag.String("input", "Burpsuite.xml", "Path to the Burp Suite XML export")
	outputPath := flag.String("output", "", "Write the plain-text table to this file")
	concurrency := flag.Int("c", 10, "Concurrent request workers")
	timeout := flag.Duration("timeout", 15*time.Second, "Timeout for each request")
	followRedirects := flag.Bool("follow", false, "Follow HTTP redirects (off by default, so 3xx responses stay visible)")
	insecure := flag.Bool("insecure", true, "Skip TLS certificate verification")
	userAgent := flag.String("ua", "RouteHound/1.0", "User-Agent header for outgoing requests")
	scope := flag.String("scope", "", "Restrict testing to these hosts and their subdomains (comma-separated, e.g. coda.io or coda.io,example.com)")
	fileInclude := flag.String("file-include", "", "Test only URLs with these file extensions (comma-separated, e.g. js or js,css)")
	fileExclude := flag.String("file-exclude", "", "Skip URLs with these file extensions (comma-separated, e.g. js or js,png,gif)")
	noColor := flag.Bool("no-color", false, "Disable ANSI colors")
	lenTolPct := flag.Int("length-tolerance", 10, "Length-match tolerance, in percent (±500 bytes floor for small responses)")
	statusMFilter := flag.String("StatusM", "", "Show only rows where StatusM is Yes or No (empty shows all)")
	lenMFilter := flag.String("LenM", "", "Show only rows where LenM is Yes or No (empty shows all)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	noBanner := flag.Bool("no-banner", false, "Hide the startup banner")

	flag.Usage = func() { printHelp(os.Stderr) }

	// Pre-scan for -no-color so help output honors it when piped.
	for _, a := range os.Args[1:] {
		if a == "-no-color" || a == "--no-color" || a == "-no-color=true" {
			colorOn = false
		}
	}
	flag.Parse()

	colorOn = !*noColor

	if *showVersion {
		fmt.Printf("%s v%s by %s\n", toolName, toolVersion, toolAuthor)
		return
	}
	if !*noBanner {
		fmt.Fprint(os.Stderr, banner()+"\n")
	}

	sFilter := normalizeYesNo(*statusMFilter)
	lFilter := normalizeYesNo(*lenMFilter)

	flt := filters{
		scopes:      splitAndNormalize(*scope, false),
		includeExts: splitAndNormalize(*fileInclude, true),
		excludeExts: splitAndNormalize(*fileExclude, true),
	}

	// ----- configuration summary ------------------------------------------
	logInfo("Loading Burp Suite export: %s", *inputPath)
	if len(flt.scopes) > 0 {
		logConfig("Scope filter       : %s  (host and all subdomains)", strings.Join(flt.scopes, ", "))
	}
	if len(flt.includeExts) > 0 {
		logConfig("Extension include  : %s", strings.Join(flt.includeExts, ", "))
	}
	if len(flt.excludeExts) > 0 {
		logConfig("Extension exclude  : %s", strings.Join(flt.excludeExts, ", "))
	}
	logConfig("Concurrency        : %d", *concurrency)
	logConfig("Request timeout    : %s", *timeout)
	logConfig("Length tolerance   : ±%d%% (minimum ±500 bytes)", *lenTolPct)
	logConfig("Follow redirects   : %s", onOff(*followRedirects))
	logConfig("TLS verification   : %s", onOff(!*insecure))
	if sFilter != "" {
		logConfig("StatusM display    : only %s", sFilter)
	}
	if lFilter != "" {
		logConfig("LenM display       : only %s", lFilter)
	}
	if *outputPath != "" {
		logConfig("Output file        : %s", *outputPath)
	}
	fmt.Fprintln(os.Stderr)

	// ----- open input -----------------------------------------------------
	f, err := os.Open(*inputPath)
	if err != nil {
		logError("Could not open %s: %v", *inputPath, err)
		os.Exit(1)
	}
	defer f.Close()

	// ----- HTTP client ----------------------------------------------------
	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
			MaxIdleConns:    200,
			MaxConnsPerHost: *concurrency,
			IdleConnTimeout: 30 * time.Second,
		},
	}
	if !*followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// ----- output file ----------------------------------------------------
	var outFile *os.File
	var outMu sync.Mutex
	if *outputPath != "" {
		outFile, err = os.Create(*outputPath)
		if err != nil {
			logError("Could not create %s: %v", *outputPath, err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	// ----- table header ---------------------------------------------------
	widths := []int{6, 60, 11, 10, 13, 12, 8, 8}
	headers := []string{"S.No", "URL", "Burp Status", "Burp Len", "Unauth Status", "Unauth Len", "StatusM", "LenM"}
	printRow(os.Stdout, headers, widths)
	printSep(os.Stdout, widths)
	if outFile != nil {
		printRow(outFile, headers, widths)
		printSep(outFile, widths)
	}

	// ----- worker pool ----------------------------------------------------
	jobs := make(chan job, *concurrency*4)
	var wg sync.WaitGroup
	var matchedStatus, matchedLength, errored, total int64

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := Result{
					SNo:        j.index,
					URL:        strings.TrimSpace(j.item.URL),
					Method:     strings.ToUpper(strings.TrimSpace(j.item.Method)),
					BurpStatus: strings.TrimSpace(j.item.Status),
					BurpLength: strings.TrimSpace(j.item.ResponseLength),
				}
				if r.Method == "" {
					r.Method = "GET"
				}

				status, length, err := doRequest(client, r.Method, r.URL, *userAgent)
				if err != nil {
					r.Error = err.Error()
					r.UnauthStatus = "ERR"
					r.UnauthLength = "-"
					r.MatchStatus = "No"
					r.MatchLength = "No"
					atomic.AddInt64(&errored, 1)
				} else {
					r.UnauthStatus = fmt.Sprintf("%d", status)
					r.UnauthLength = fmt.Sprintf("%d", length)
					r.MatchStatus = yesNo(r.BurpStatus == r.UnauthStatus)
					r.MatchLength = yesNo(lengthWithin(r.BurpLength, r.UnauthLength, *lenTolPct))
					if r.MatchStatus == "Yes" {
						atomic.AddInt64(&matchedStatus, 1)
					}
					if r.MatchLength == "Yes" {
						atomic.AddInt64(&matchedLength, 1)
					}
				}
				atomic.AddInt64(&total, 1)

				if sFilter != "" && r.MatchStatus != sFilter {
					continue
				}
				if lFilter != "" && r.MatchLength != lFilter {
					continue
				}

				plain := []string{
					padRight(fmt.Sprintf("%d", r.SNo), widths[0]),
					padRight(truncate(r.URL, widths[1]), widths[1]),
					padRight(r.BurpStatus, widths[2]),
					padRight(r.BurpLength, widths[3]),
					padRight(r.UnauthStatus, widths[4]),
					padRight(r.UnauthLength, widths[5]),
					padRight(r.MatchStatus, widths[6]),
					padRight(r.MatchLength, widths[7]),
				}
				plainLine := "| " + strings.Join(plain, " | ") + " |"

				colored := make([]string, len(plain))
				copy(colored, plain)
				colored[6] = colorMatch(plain[6], r.MatchStatus)
				colored[7] = colorMatch(plain[7], r.MatchLength)
				coloredLine := "| " + strings.Join(colored, " | ") + " |"

				fmt.Fprintln(os.Stdout, coloredLine)
				if outFile != nil {
					outMu.Lock()
					fmt.Fprintln(outFile, plainLine)
					outMu.Unlock()
				}
			}
		}()
	}

	// ----- streaming XML parser ------------------------------------------
	logInfo("Parsing XML and dispatching requests...")
	decoder := xml.NewDecoder(f)
	index := 0
	skipped := 0
	start := time.Now()

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			logError("XML parse error at offset %d: %v", decoder.InputOffset(), err)
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "item" {
			continue
		}
		var it BurpItem
		if err := decoder.DecodeElement(&it, &se); err != nil {
			logWarn("Could not decode <item>: %v", err)
			continue
		}

		if !flt.allow(strings.TrimSpace(it.URL)) {
			skipped++
			continue
		}
		index++
		jobs <- job{index: index, item: it}

		if index%500 == 0 {
			logProgress("Dispatched %d URLs  (%d filtered out, %.1fs elapsed)",
				index, skipped, time.Since(start).Seconds())
		}
	}
	close(jobs)
	wg.Wait()

	// ----- footer and summary --------------------------------------------
	printSep(os.Stdout, widths)
	if outFile != nil {
		printSep(outFile, widths)
	}
	elapsed := time.Since(start)
	fmt.Fprintln(os.Stderr)
	logDone("Scan complete.")

	stats := [][2]string{
		{"URLs tested", fmt.Sprintf("%d", total)},
		{"Filtered out by scope/extension", fmt.Sprintf("%d", skipped)},
		{"Status matches", fmt.Sprintf("%d", matchedStatus)},
		{"Length matches", fmt.Sprintf("%d", matchedLength)},
		{"Errored", fmt.Sprintf("%d", errored)},
		{"Duration", fmt.Sprintf("%.1fs", elapsed.Seconds())},
	}
	if *outputPath != "" {
		stats = append(stats, [2]string{"Report written to", *outputPath})
	}
	for _, s := range stats {
		fmt.Fprintf(os.Stderr, "    %-32s : %s\n", s[0], s[1])
	}

	if outFile != nil {
		fmt.Fprintln(outFile)
		fmt.Fprintln(outFile, "Scan complete.")
		for _, s := range stats {
			fmt.Fprintf(outFile, "    %-32s : %s\n", s[0], s[1])
		}
	}
}

// ---------------------------------------------------------------------------
// Filtering helpers
// ---------------------------------------------------------------------------

func (f filters) allow(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())

	if len(f.scopes) > 0 {
		matched := false
		for _, s := range f.scopes {
			if host == s || strings.HasSuffix(host, "."+s) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	ext := strings.ToLower(strings.TrimPrefix(path.Ext(u.Path), "."))

	if len(f.includeExts) > 0 {
		hit := false
		for _, e := range f.includeExts {
			if ext == e {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}

	if len(f.excludeExts) > 0 {
		for _, e := range f.excludeExts {
			if ext == e {
				return false
			}
		}
	}
	return true
}

func splitAndNormalize(s string, stripDot bool) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if stripDot {
			p = strings.TrimPrefix(p, ".")
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP + length math
// ---------------------------------------------------------------------------

func doRequest(client *http.Client, method, u, ua string) (int, int64, error) {
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.Copy(io.Discard, resp.Body)
	// Match Burp's <responselength>: status line + headers + CRLF + body.
	headerBytes := len(resp.Proto) + 1 + len(resp.Status) + 2
	for k, vs := range resp.Header {
		for _, v := range vs {
			headerBytes += len(k) + 2 + len(v) + 2
		}
	}
	headerBytes += 2
	return resp.StatusCode, int64(headerBytes) + bodyBytes, nil
}

func lengthWithin(a, b string, tolPct int) bool {
	ai, err1 := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
	bi, err2 := strconv.ParseInt(strings.TrimSpace(b), 10, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	diff := ai - bi
	if diff < 0 {
		diff = -diff
	}
	ref := ai
	if bi > ref {
		ref = bi
	}
	allowed := ref * int64(tolPct) / 100
	if allowed < 500 {
		allowed = 500
	}
	return diff <= allowed
}

// ---------------------------------------------------------------------------
// Yes/No helpers
// ---------------------------------------------------------------------------

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func normalizeYesNo(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ""
	case "yes", "y", "true", "1":
		return "Yes"
	case "no", "n", "false", "0":
		return "No"
	default:
		logWarn("Ignoring unrecognized Yes/No value: %q", s)
		return ""
	}
}

func colorMatch(padded, raw string) string {
	if !colorOn {
		return padded
	}
	switch raw {
	case "Yes":
		return cBoldGreen + padded + cReset
	case "No":
		return cBoldRed + padded + cReset
	}
	return padded
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

func printRow(w io.Writer, cells []string, widths []int) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		parts[i] = padRight(c, widths[i])
	}
	fmt.Fprintln(w, "| "+strings.Join(parts, " | ")+" |")
}

func printSep(w io.Writer, widths []int) {
	parts := make([]string, len(widths))
	for i, width := range widths {
		parts[i] = strings.Repeat("-", width)
	}
	fmt.Fprintln(w, "+-"+strings.Join(parts, "-+-")+"-+")
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

// ---------------------------------------------------------------------------
// Help (table-formatted flag reference)
// ---------------------------------------------------------------------------

type flagRow struct{ name, typ, def, desc string }

type flagSection struct {
	title string
	rows  []flagRow
}

var helpSections = []flagSection{
	{"Input & Output", []flagRow{
		{"-input", "string", "Burpsuite.xml", "Path to the Burp Suite XML export"},
		{"-output", "string", "(none)", "Write the plain-text table to this file"},
	}},
	{"Scanning", []flagRow{
		{"-c", "int", "10", "Concurrent request workers"},
		{"-timeout", "duration", "15s", "Timeout for each request"},
		{"-ua", "string", "RouteHound/1.0", "User-Agent header for outgoing requests"},
		{"-insecure", "bool", "true", "Skip TLS certificate verification"},
		{"-follow", "bool", "false", "Follow HTTP redirects (off keeps 3xx visible)"},
	}},
	{"Scope & Filtering", []flagRow{
		{"-scope", "string", "(none)", "Restrict to these hosts and their subdomains (comma-separated)"},
		{"-file-include", "string", "(none)", "Test only URLs with these file extensions (comma-separated)"},
		{"-file-exclude", "string", "(none)", "Skip URLs with these file extensions (comma-separated)"},
		{"-length-tolerance", "int", "10", "Length-match tolerance in percent (floor: 500 bytes)"},
	}},
	{"Display Filters", []flagRow{
		{"-StatusM", "string", "(none)", "Show only rows where StatusM equals Yes or No"},
		{"-LenM", "string", "(none)", "Show only rows where LenM equals Yes or No"},
		{"-no-color", "bool", "false", "Disable ANSI colors"},
		{"-no-banner", "bool", "false", "Hide the startup banner"},
	}},
	{"Meta", []flagRow{
		{"-version", "bool", "false", "Print version and exit"},
		{"-help", "bool", "false", "Show this help message"},
	}},
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, banner()+"\n")
	fmt.Fprintln(w, paint(cBoldCyan, "USAGE"))
	fmt.Fprintf(w, "  %s [flags]\n\n", os.Args[0])

	widths := []int{18, 9, 16, 62}
	header := []string{"Flag", "Type", "Default", "Description"}

	for _, sec := range helpSections {
		fmt.Fprintln(w, paint(cBoldCyan, strings.ToUpper(sec.title)))
		printTableSep(w, widths)
		printTableHead(w, header, widths)
		printTableSep(w, widths)
		for _, r := range sec.rows {
			cells := []string{
				padRight(r.name, widths[0]),
				padRight(r.typ, widths[1]),
				padRight(r.def, widths[2]),
				padRight(r.desc, widths[3]),
			}
			cells[0] = colorizeCell(cells[0], cGreen)
			cells[1] = colorizeCell(cells[1], cDim)
			cells[2] = colorizeCell(cells[2], cYellow)
			fmt.Fprintln(w, "| "+strings.Join(cells, " | ")+" |")
		}
		printTableSep(w, widths)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, paint(cBoldCyan, "EXAMPLES"))
	examples := []string{
		"# Scan everything in scope coda.io, write report, 50 workers",
		fmt.Sprintf("  %s -input Burpsuite.xml -scope coda.io -output report.txt -c 50", os.Args[0]),
		"",
		"# Skip static assets, show only the forced-browsing candidates",
		fmt.Sprintf("  %s -input Burpsuite.xml -scope coda.io -file-exclude js,css,png,gif,svg,woff,woff2 -StatusM Yes -LenM Yes", os.Args[0]),
		"",
		"# Only JavaScript files",
		fmt.Sprintf("  %s -input Burpsuite.xml -file-include js", os.Args[0]),
	}
	for _, e := range examples {
		if strings.HasPrefix(strings.TrimSpace(e), "#") {
			fmt.Fprintln(w, "  "+paint(cDim, e))
		} else {
			fmt.Fprintln(w, e)
		}
	}
	fmt.Fprintln(w)
}

func printTableSep(w io.Writer, widths []int) {
	parts := make([]string, len(widths))
	for i, width := range widths {
		parts[i] = strings.Repeat("-", width)
	}
	fmt.Fprintln(w, "+-"+strings.Join(parts, "-+-")+"-+")
}

func printTableHead(w io.Writer, cells []string, widths []int) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		parts[i] = colorizeCell(padRight(c, widths[i]), cBoldCyan)
	}
	fmt.Fprintln(w, "| "+strings.Join(parts, " | ")+" |")
}

func colorizeCell(padded, code string) string {
	if !colorOn {
		return padded
	}
	return code + padded + cReset
}
