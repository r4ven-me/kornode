# Source material summary

The current public project describes an OpenConnect/ocserv container with optional upstream OpenConnect client, split tunneling via dnsmasq+nftables and OTP via ocpasswd.

The original VPN server article focuses on running ocserv over HTTPS in Docker for internal projects, certificate/user generation, client artifacts and practical deployment.

The middle-server article focuses on a server that accepts user VPN connections, starts its own OpenConnect client connection to a private contour and routes user traffic into that contour.

The OpenWrt article is relevant for split routing concepts: full traffic, selected domains, selected IP/subnets and DNS-assisted routing.

The ocserv sample config is the canonical reference for supported ocserv parameters. The new project should implement the common safe subset first and provide an advanced raw-options mechanism for less common options.
