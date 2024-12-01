// 
//  * SuSDNS - Proprietary Software
//  * Copyright (c) 2024 Rushikesh Muley. All rights reserved.
//  *
//  * This file is part of SuSDNS. Unauthorized copying, modification, or distribution of this file,
//  * via any medium, is strictly prohibited without prior written permission from the author.
//  *
//  * For inquiries, contact: Rushikesh Muley (rushikeshmuley@outlook.com)
//  

package dgadetect

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type DGADetect struct {
	Next           plugin.Handler
	FlaskServerURL string
	UpstreamDNS    string // Upstream DNS server (e.g., 8.8.8.8:53)
	RedirectIP     string // IP address to redirect DGA domains to
}

func (d DGADetect) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	domain := state.Name()

	// Extract the client's IP address
	clientIP, _, err := net.SplitHostPort(state.IP())
	if err != nil {
		log.Warningf("Unable to parse client IP: %v", err)
		clientIP = "unknown"
	}

	// Create a new HTTP client with a timeout
	client := &http.Client{Timeout: 5 * time.Second}

	// Send request to Flask server
	resp, err := client.Post(d.FlaskServerURL, "application/json", strings.NewReader(`{"domain":"`+domain+`"}`))
	if err != nil {
		log.Warningf("Error contacting Flask server: %v", err)
		return d.forwardRequest(ctx, w, r) // Forward request if Flask server fails
	}
	defer resp.Body.Close()

	var result struct {
		Domain string `json:"domain"`
		Label  string `json:"label"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Warningf("Error decoding Flask server response: %v", err)
		return d.forwardRequest(ctx, w, r) // Forward request if decoding fails
	}

	if result.Label == "dga" {
		log.Errorf("[Warning]: Domain %s classified as DGA. Client IP: %s", domain, clientIP)

		// Create a DNS response to redirect to the specified IP
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		// Set A record for redirection
		rr, err := dns.NewRR(domain + " 60 IN A " + d.RedirectIP)
		if err != nil {
			log.Errorf("Failed to create DNS record for redirect: %v", err)
			return dns.RcodeServerFailure, err
		}
		m.Answer = append(m.Answer, rr)

		// Send response
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	log.Infof("Domain %s not classified as DGA, forwarding to upstream DNS. Client IP: %s", domain, clientIP)
	return d.forwardRequest(ctx, w, r)
}

func (d DGADetect) forwardRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	c := new(dns.Client)
	resp, _, err := c.Exchange(r, d.UpstreamDNS)
	if err != nil {
		log.Errorf("Error forwarding request to upstream DNS %s: %v", d.UpstreamDNS, err)
		return dns.RcodeServerFailure, err
	}

	w.WriteMsg(resp) // Write the response from the upstream DNS server
	return dns.RcodeSuccess, nil
}

func (d DGADetect) Name() string { return "dgadetect" }
