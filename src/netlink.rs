//! Implements `netlink(3)` functionality
//!
//! All functions here create and close a netlink socket on each call.
//! This is redundant but ensures security, by avoiding having privileged sockets
//! lingering around, once the appropriate capabilities have been dropped.
//!
//! The code is largely based upon the internals of the `rtnetlink crate`, thank you!

use std::net::IpAddr;

use anyhow::{bail, Result};
use log::debug;
use netlink_packet_core::{
    ErrorMessage, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlags, LinkMessage},
    route::{RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

const DEFAULT_BUF_SIZE: usize = 4096;

/// Create a netlink socket and bind it properly
fn create_socket(protocol: isize) -> Result<Socket> {
    let mut socket = Socket::new(protocol)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    Ok(socket)
}

/// Send `msg` over `socket` and ensure that it has been fully sent
fn send<I: NetlinkSerializable>(socket: &mut Socket, msg: &NetlinkMessage<I>) -> Result<()> {
    // Serialize msg
    let mut buf = vec![0; msg.header.length as usize];
    msg.serialize(&mut buf);

    // Send the message
    let n = socket.send(&buf[..], 0)?;
    if n != buf.len() {
        bail!("netlink sent {n} bytes instead of {} bytes", buf.len());
    }

    Ok(())
}

/// Receive on `socket` and deserialize into `I`
fn recv<I: NetlinkDeserializable>(socket: &mut Socket) -> Result<NetlinkMessage<I>> {
    let mut buf = vec![0_u8; DEFAULT_BUF_SIZE];
    socket.recv(&mut &mut buf[..], 0)?;

    Ok(NetlinkMessage::deserialize(&buf)?)
}

/// Return the index of an interface given by its name
pub fn get_index(name: &str) -> Result<u32> {
    let mut socket = create_socket(NETLINK_ROUTE)?;
    debug!("created netlink socket to find {name}");

    // Construct the netlink message
    let mut link_msg = LinkMessage::default();
    link_msg.attributes.push(LinkAttribute::IfName(name.into()));
    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(link_msg)),
    );
    msg.header.flags = NLM_F_REQUEST;
    msg.header.sequence_number = 1;
    msg.finalize();

    send(&mut socket, &msg)?;
    let resp: NetlinkMessage<RouteNetlinkMessage> = recv(&mut socket)?;

    // Parse it down
    let resp = match resp.payload {
        NetlinkPayload::InnerMessage(msg) => msg,
        _ => bail!("did not received NetlinkPayload::InnerMessage"),
    };
    let resp = match resp {
        RouteNetlinkMessage::NewLink(msg) => msg,
        _ => bail!("inner message is not of type RouteNetlinkMessage::NewLink"),
    };

    // Check whether the returned attributes do contain an interface named `name`
    let exists = resp.attributes.iter().any(|attr| match attr {
        LinkAttribute::IfName(iname) => iname == name,
        _ => false,
    });
    if !exists {
        bail!("interface {name} does not seem to exist");
    }

    // Finally, return the index of the interface
    Ok(resp.header.index)
}

/// Set an interface up
pub fn set_up(index: u32) -> Result<()> {
    let mut socket = create_socket(NETLINK_ROUTE)?;
    debug!("created netlink socket to set {index} UP");

    let mut link_msg = LinkMessage::default();
    link_msg.header.index = index;
    link_msg.header.flags = LinkFlags::Up;
    link_msg.header.change_mask = LinkFlags::Up;
    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::SetLink(link_msg)),
    );
    msg.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    msg.finalize();

    send(&mut socket, &msg)?;
    let resp: NetlinkMessage<RouteNetlinkMessage> = recv(&mut socket)?;

    // Check for errors (ACK is Error with code zero)
    match resp.payload {
        NetlinkPayload::Error(ErrorMessage { code: None, .. }) => {}
        _ => bail!("netlink failed for unknown reasons while setting {index} UP"),
    }
    debug!("setted interface {index} to UP");

    Ok(())
}

/// Move the network device to the network namespace of `pid`
pub fn set_ns(index: u32, pid: u32) -> Result<()> {
    let mut socket = create_socket(NETLINK_ROUTE)?;
    debug!("created netlink socket to move {index} to NS of {pid}");

    let mut link_msg = LinkMessage::default();
    link_msg.header.index = index;
    link_msg.attributes.push(LinkAttribute::NetNsPid(pid));
    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::SetLink(link_msg)),
    );
    msg.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    msg.finalize();

    send(&mut socket, &msg)?;
    let resp: NetlinkMessage<RouteNetlinkMessage> = recv(&mut socket)?;

    // Check for errors (ACK is Error with code zero)
    match resp.payload {
        NetlinkPayload::Error(ErrorMessage { code: None, .. }) => {}
        e => bail!(
            "netlink failed for unknown reasons moving {index} to NS of {pid} {:#?}",
            e
        ),
    }
    debug!("moved interface {index} to NS of {pid}");

    Ok(())
}

/// Add `addr` to interface `index`
pub fn add_address(index: u32, addr: IpAddr, prefix_len: u8) -> Result<()> {
    let mut socket = create_socket(NETLINK_ROUTE)?;
    debug!("created socket for adding an IP address to {index}");

    let mut addr_msg = AddressMessage::default();

    addr_msg.header.prefix_len = prefix_len;
    addr_msg.header.index = index;

    addr_msg.header.family = match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };

    // TODO: Not implementing multicast/broadcast here, not needed
    addr_msg.attributes.push(AddressAttribute::Address(addr));
    addr_msg.attributes.push(AddressAttribute::Local(addr));

    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::NewAddress(addr_msg)),
    );
    msg.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    msg.finalize();

    send(&mut socket, &msg)?;
    let resp: NetlinkMessage<RouteNetlinkMessage> = recv(&mut socket)?;

    // Check for errors (ACK is Error with code zero)
    match resp.payload {
        NetlinkPayload::Error(ErrorMessage { code: None, .. }) => {}
        _ => bail!("netlink failed for unknown reasons adding IP to {index}"),
    }
    debug!("added IP to {index}");

    Ok(())
}

/// Sets the interface with `index` as the default gateway for `af`
///
/// TODO: Consider not exposing `AddressFamily` here
pub fn set_default_gateway(index: u32, af: AddressFamily) -> Result<()> {
    let mut socket = create_socket(NETLINK_ROUTE)?;
    debug!("created socket for adding default gateway for {:?}", af);

    let mut route_msg = RouteMessage::default();
    route_msg.header.table = RouteHeader::RT_TABLE_MAIN;
    route_msg.header.protocol = RouteProtocol::Static;
    route_msg.header.scope = RouteScope::Universe;
    route_msg.header.kind = RouteType::Unicast;
    route_msg.header.address_family = af;

    route_msg.attributes.push(RouteAttribute::Oif(index));

    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::NewRoute(route_msg)),
    );
    msg.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    msg.finalize();

    send(&mut socket, &msg)?;
    let resp: NetlinkMessage<RouteNetlinkMessage> = recv(&mut socket)?;

    // Check for errors (ACK is Error with code zero)
    match resp.payload {
        NetlinkPayload::Error(ErrorMessage { code: None, .. }) => {}
        e => bail!(
            "netlink failed for unknown reasons default gateway {:?} {:#?}",
            af,
            e
        ),
    }
    debug!("added default gateway {:?}", af);

    Ok(())
}
