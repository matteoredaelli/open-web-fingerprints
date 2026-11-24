// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package checks

import "strings"

// A host matches a needle when it is the needle or a subdomain of it. A needle that ends in
// "-" matches a label that starts with it (awsdns-12.com).
type needle struct{ host, name string }

// mxProviders are services recognised from the host names of MX records.
var mxProviders = []needle{
	{"google.com", "Google Workspace"}, {"googlemail.com", "Google Workspace"},
	{"mail.protection.outlook.com", "Microsoft 365"}, {"outlook.com", "Microsoft 365"},
	{"pphosted.com", "Proofpoint"}, {"ppe-hosted.com", "Proofpoint Essentials"},
	{"mimecast.com", "Mimecast"}, {"mimecast-offshore.com", "Mimecast"},
	{"zoho.com", "Zoho Mail"}, {"zoho.eu", "Zoho Mail"},
	{"messagingengine.com", "Fastmail"}, {"protonmail.ch", "Proton Mail"}, {"icloud.com", "iCloud Mail"},
	{"yahoodns.net", "Yahoo Mail"}, {"secureserver.net", "GoDaddy"},
	{"ionos.com", "IONOS"}, {"ionos.it", "IONOS"}, {"kundenserver.de", "IONOS"}, {"1and1.com", "IONOS"},
	{"ovh.net", "OVHcloud"}, {"aruba.it", "Aruba"}, {"register.it", "Register.it"},
	{"mailgun.org", "Mailgun"}, {"barracudanetworks.com", "Barracuda"}, {"iphmx.com", "Cisco Secure Email"},
	{"trendmicro.eu", "Trend Micro"}, {"trendmicro.com", "Trend Micro"}, {"forcepoint.net", "Forcepoint"},
	{"hornetsecurity.com", "Hornetsecurity"}, {"antispameurope.com", "Hornetsecurity"},
	{"yandex.net", "Yandex"}, {"yandex.ru", "Yandex"}, {"privateemail.com", "Namecheap Private Email"},
	{"messagelabs.com", "Symantec Email Security"}, {"cf-emailsecurity.net", "Cloudflare Email Security"},
	{"sophos.com", "Sophos Email"},
}

// spfProviders are services recognised from the include: and redirect= targets of an SPF record.
var spfProviders = []needle{
	{"_spf.google.com", "Google Workspace"}, {"google.com", "Google Workspace"},
	{"spf.protection.outlook.com", "Microsoft 365"},
	{"sendgrid.net", "SendGrid"}, {"mailgun.org", "Mailgun"}, {"amazonses.com", "Amazon SES"},
	{"mandrillapp.com", "Mailchimp Transactional"}, {"mcsv.net", "Mailchimp"}, {"mailchimp.com", "Mailchimp"},
	{"mailjet.com", "Mailjet"}, {"sparkpostmail.com", "SparkPost"}, {"zoho.com", "Zoho"}, {"zoho.eu", "Zoho"},
	{"salesforce.com", "Salesforce"}, {"hubspotemail.net", "HubSpot"}, {"zendesk.com", "Zendesk"},
	{"freshdesk.com", "Freshworks"}, {"postmarkapp.com", "Postmark"}, {"sendinblue.com", "Brevo"}, {"brevo.com", "Brevo"},
	{"mimecast.com", "Mimecast"}, {"pphosted.com", "Proofpoint"}, {"secureserver.net", "GoDaddy"},
	{"mlsend.com", "MailerLite"}, {"atlassian.net", "Atlassian"}, {"messagelabs.com", "Symantec Email Security"},
	{"icloud.com", "iCloud Mail"}, {"intercom.io", "Intercom"}, {"cf-emailsecurity.net", "Cloudflare Email Security"},
	{"sophos.com", "Sophos Email"},
}

// nsProviders are services recognised from the host names of NS records.
var nsProviders = []needle{
	{"cloudflare.com", "Cloudflare"}, {"awsdns-", "Amazon Route 53"},
	{"azure-dns.com", "Azure DNS"}, {"azure-dns.net", "Azure DNS"}, {"azure-dns.org", "Azure DNS"}, {"azure-dns.info", "Azure DNS"},
	{"googledomains.com", "Google Cloud DNS"}, {"akam.net", "Akamai"}, {"akamai.net", "Akamai"},
	{"ultradns.net", "UltraDNS"}, {"ultradns.com", "UltraDNS"}, {"ultradns.org", "UltraDNS"}, {"ultradns.biz", "UltraDNS"},
	{"dnsmadeeasy.com", "DNS Made Easy"}, {"domaincontrol.com", "GoDaddy"}, {"registrar-servers.com", "Namecheap"},
	{"nsone.net", "NS1"}, {"dynect.net", "Oracle Dyn"}, {"gandi.net", "Gandi"}, {"ovh.net", "OVHcloud"}, {"anycast.me", "OVHcloud"},
	{"ui-dns.com", "IONOS"}, {"ui-dns.de", "IONOS"}, {"ui-dns.org", "IONOS"}, {"ui-dns.biz", "IONOS"},
	{"wixdns.net", "Wix"}, {"digitalocean.com", "DigitalOcean"}, {"hetzner.com", "Hetzner"}, {"register.it", "Register.it"},
	{"aruba.it", "Aruba"}, {"linode.com", "Linode"}, {"squarespacedns.com", "Squarespace"}, {"vercel-dns.com", "Vercel"},
	{"cloudns.net", "ClouDNS"},
}

// recognise returns the name of the first needle that host matches.
func recognise(list []needle, host string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, n := range list {
		if h == n.host || strings.HasSuffix(h, "."+n.host) {
			return n.name, true
		}
		if strings.HasSuffix(n.host, "-") && (strings.HasPrefix(h, n.host) || strings.Contains(h, "."+n.host)) {
			return n.name, true
		}
	}
	return "", false
}
