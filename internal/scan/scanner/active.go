// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"net/url"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/engine"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// ActiveOptions control the probes sent with --active.
type ActiveOptions struct {
	Fetch fetch.Options
	// Max is how many requests to send at most (default DefaultActiveMax); the probes shared
	// by most rules go first.
	Max int
	// Delay is the pause before each request.
	Delay time.Duration
}

// DefaultActiveMax bounds the requests one scan sends to the site beyond the page it was asked for.
const DefaultActiveMax = 30

// maxProbeBody is how much of an answer is kept for the rules.
const maxProbeBody = 1 << 20

// Probed is what the probes found.
type Probed struct {
	Responses map[string]matcher.ProbeResponse // by path
	Sent      map[string]bool
	Report    scan.Active
	Warnings  []scan.Warning
}

// RunProbes sends the approved probes to the site that was scanned. It is the only place
// where the scanner asks a site for a page it was not told to read, so it is strict:
//
//   - only the probes of rules whose safety review is approved, as the plan says;
//   - only GET, only a path that passes curate.SafePath, always on the scanned host;
//   - robots.txt is read first (a server error means no probes) and a disallowed path is not
//     requested; there is no option to override this;
//   - a pause before each request, at most Max requests, the same guard against non-public
//     addresses as every other request;
//   - an answer from another registrable domain (a redirect away) is thrown away.
//
// What was not sent is counted, with the reason, in the report.
func RunProbes(ctx context.Context, opt ActiveOptions, origin *url.URL, site string, plan []engine.ProbePlan) *Probed {
	if opt.Max <= 0 {
		opt.Max = DefaultActiveMax
	}
	out := &Probed{Responses: map[string]matcher.ProbeResponse{}, Sent: map[string]bool{}}
	rep := &out.Report
	rep.Approved = len(plan)
	base := origin.Scheme + "://" + origin.Host
	f := fetch.New(opt.Fetch)
	rules, _, ok, rerr := fetchRobotsErr(ctx, f, base)
	if rerr != nil || !ok {
		rep.NotSent = len(plan)
		out.Warnings = append(out.Warnings, scan.Warning{Code: "probes_not_sent",
			Message: "robots.txt could not be read, so no probe was sent", Ref: base})
		return out
	}
	for _, p := range plan {
		switch {
		case ctx.Err() != nil:
			rep.NotSent++
			continue
		case p.Method != "GET" || curate.SafePath(p.Path) != nil:
			rep.NotSent++
			rep.Refused++
			continue
		case !rules.Allowed(base + p.Path):
			rep.NotSent++
			rep.Disallowed++
			continue
		case rep.Sent >= opt.Max:
			rep.NotSent++
			continue
		}
		if !sleep(ctx, opt.Delay) {
			rep.NotSent++
			continue
		}
		resp, err := f.Get(ctx, base+p.Path)
		rep.Sent++
		if err != nil {
			rep.Failed++
			continue
		}
		if final, err := url.Parse(resp.FinalURL); err != nil || web.RegistrableDomain(final.Hostname()) != site {
			rep.Failed++
			continue
		}
		body := resp.Body
		if len(body) > maxProbeBody {
			body = body[:maxProbeBody]
		}
		hdr := map[string]string{}
		for k, vs := range resp.Header {
			if len(vs) > 0 {
				hdr[k] = vs[0]
			}
		}
		out.Responses[p.Path] = matcher.ProbeResponse{Status: resp.Status, Headers: hdr, Body: string(body)}
		out.Sent[p.Path] = true
	}
	if rep.NotSent > 0 {
		out.Warnings = append(out.Warnings, scan.Warning{Code: "probes_not_all_sent",
			Message: "some approved probes were not sent (limit, robots.txt or a refused path)", Ref: base})
	}
	return out
}
