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
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    "github.com/coredns/caddy"
)

func init() {
    plugin.Register("dgadetect", setup)
}

func setup(c *caddy.Controller) error {
    d := DGADetect{
        FlaskServerURL: "http://172.26.80.1:5000/isDGA",
        UpstreamDNS:    "8.8.8.8:53", // Default upstream DNS
        RedirectIP:    "172.26.80.1", // Default upstream DNS
    }

    c.Next() // Consume the directive name
    for c.NextBlock() {
        switch c.Val() {
        case "url":
            if !c.NextArg() {
                return plugin.Error("dgadetect", c.ArgErr())
            }
            d.FlaskServerURL = c.Val()
        case "upstream":
            if !c.NextArg() {
                return plugin.Error("dgadetect", c.ArgErr())
            }
            d.UpstreamDNS = c.Val()
        default:
            return plugin.Error("dgadetect", c.Errf("unknown property '%s'", c.Val()))
        }
    }

    if d.FlaskServerURL == "" {
        return plugin.Error("dgadetect", c.Err("Flask server URL must be specified"))
    }

    if d.UpstreamDNS == "" {
        return plugin.Error("dgadetect", c.Err("Upstream DNS server must be specified"))
    }

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        d.Next = next
        return d
    })

    return nil
}
