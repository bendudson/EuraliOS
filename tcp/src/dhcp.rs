//! Dynamic Host Configuration Protocol (DHCP)
//! Configure IP, DNS and gatway

use smoltcp::wire::{IpCidr, Ipv4Cidr, IpAddress};
use smoltcp::socket::{Dhcpv4Event, Dhcpv4Socket};
use smoltcp::time::Instant;

use euralios_std::{println, print,
                   syscalls};

use crate::Interface;
use crate::dns;

/// DHCP configuration on given interface
///
/// Based on <https://github.com/vinc/moros/blob/trunk/src/usr/dhcp.rs>
pub fn configure(interface: &mut Interface) {

    let dhcp_socket = Dhcpv4Socket::new();
    let dhcp_handle = interface.add_socket(dhcp_socket);

    if let Err(e) = interface.poll(Instant::from_millis(0)) { // This transmits
        panic!("[tcp] Network Error: {}", e);
    }

    loop {
        let event = interface.get_socket::<Dhcpv4Socket>(dhcp_handle).poll();
        match event {
            None => {}
            Some(Dhcpv4Event::Configured(config)) => {
                interface.remove_socket(dhcp_handle);

                print!("[tcp] DHCP: IP {}", config.address);
                set_ipv4_addr(interface, config.address);

                if let Some(router) = config.router {
                    print!(" Router {}", router);
                    interface.routes_mut().add_default_ipv4_route(router).unwrap();
                }

                for addr in config.dns_servers.iter()
                    .filter(|addr| addr.is_some()).map(|addr| addr.unwrap()) {
                        print!(" DNS {}", addr);
                        dns::add_server(IpAddress::from(addr));
                    }
                println!("");
                break;
            }
            Some(Dhcpv4Event::Deconfigured) => {
            }
        }
        // Wait and retry
        syscalls::thread_yield();
    }
}

/// Set the IPv4 address of an interface
///
/// This function from:
/// <https://github.com/smoltcp-rs/smoltcp/blob/master/examples/dhcp_client.rs#L97>
fn set_ipv4_addr(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        let dest = addrs.iter_mut().next().unwrap();
        *dest = IpCidr::Ipv4(cidr);
    });
}
