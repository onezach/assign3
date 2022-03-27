package edu.wisc.cs.sdn.vnet.rt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	public void startRip() {
		
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{ 
			// set up pack headers
			Ethernet ether = new Ethernet();
			IPv4 ip = new IPv4();
			ICMP icmp = new ICMP();
			Data data = new Data();
			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);
			
			// set ether packet header fields
			ether.setEtherType(Ethernet.TYPE_IPv4);
			ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

			IPv4 ethPayload = (IPv4)etherPacket.getPayload();

			int macSRC = ethPayload.getSourceAddress();

			// Find matching route table entry 
			RouteEntry prev = this.routeTable.lookup(macSRC);
			
			int nextHop = prev.getGatewayAddress();
			if (0 == nextHop)
			{ nextHop = macSRC; }

			// Set destination MAC address in Ethernet header
			ArpEntry arpEntry = this.arpCache.lookup(nextHop);
			ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

			// set IP header fields
			ip.setTtl((byte) 64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(inIface.getIpAddress());
			ip.setDestinationAddress(ethPayload.getSourceAddress());

			// set ICMP header fields
			icmp.setIcmpType((byte) 11);
			icmp.setIcmpCode((byte) 0);

			// extract etherPacket payload and format into ICMP payload
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] padding = new byte[4];
			try {
				baos.write(padding);
				baos.write(ethPayload.serialize());
			} catch (IOException e) {
				e.printStackTrace();
			}

			// convert to proper size and set data
			byte[] fullPayload = baos.toByteArray();
			byte[] partialPayload = new byte[4 + (ethPayload.getHeaderLength()*4) + 8];
			for (int i = 0; i < partialPayload.length; i++) {
				partialPayload[i] = fullPayload[i];
			}
			data.setData(partialPayload);
			
			this.sendPacket(ether, inIface);
			return; 
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{ return; }
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{ 
			// set up pack headers
			Ethernet ether = new Ethernet();
			IPv4 ip = new IPv4();
			ICMP icmp = new ICMP();
			Data data = new Data();
			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);

			// set ether packet header fields
			ether.setEtherType(Ethernet.TYPE_IPv4);
			ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

			IPv4 ethPayload = (IPv4)etherPacket.getPayload();

			int macSRC = ethPayload.getSourceAddress();

			// Find matching route table entry 
			RouteEntry prev = this.routeTable.lookup(macSRC);

			int nextHop = prev.getGatewayAddress();
			if (0 == nextHop)
			{ nextHop = macSRC; }

			// Set destination MAC address in Ethernet header
			ArpEntry arpEntry = this.arpCache.lookup(nextHop);
			ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

			// set IP header fields
			ip.setTtl((byte) 64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(inIface.getIpAddress());
			ip.setDestinationAddress(ethPayload.getSourceAddress());

			// set ICMP header fields
			icmp.setIcmpType((byte) 3);
			icmp.setIcmpCode((byte) 0);

			// extract etherPacket payload and format into ICMP payload
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] padding = new byte[4];
			try {
				baos.write(padding);
				baos.write(ethPayload.serialize());
			} catch (IOException e) {
				e.printStackTrace();
			}

			// convert to proper size and set data
			byte[] fullPayload = baos.toByteArray();
			byte[] partialPayload = new byte[4 + (ethPayload.getHeaderLength()*4) + 8];
			for (int i = 0; i < partialPayload.length; i++) {
				partialPayload[i] = fullPayload[i];
			}
			data.setData(partialPayload);

			this.sendPacket(ether, inIface);
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ 
			if (etherPacket.getEtherType() == IPv4.PROTOCOL_UDP || etherPacket.getEtherType() == IPv4.PROTOCOL_TCP) {
				// set up pack headers
				Ethernet ether = new Ethernet();
				IPv4 ip = new IPv4();
				ICMP icmp = new ICMP();
				Data data = new Data();
				ether.setPayload(ip);
				ip.setPayload(icmp);
				icmp.setPayload(data);

				// set ether packet header fields
				ether.setEtherType(Ethernet.TYPE_IPv4);
				ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

				IPv4 ethPayload = (IPv4)etherPacket.getPayload();

				int macSRC = ethPayload.getSourceAddress();

				// Find matching route table entry 
				RouteEntry prev = this.routeTable.lookup(macSRC);

				int nextHop1 = prev.getGatewayAddress();
				if (0 == nextHop1)
				{ nextHop1 = macSRC; }

				// Set destination MAC address in Ethernet header
				ArpEntry arpEntry1 = this.arpCache.lookup(nextHop1);
				ether.setDestinationMACAddress(arpEntry1.getMac().toBytes());

				// set IP header fields
				ip.setTtl((byte) 64);
				ip.setProtocol(IPv4.PROTOCOL_ICMP);
				ip.setSourceAddress(inIface.getIpAddress());
				ip.setDestinationAddress(ethPayload.getSourceAddress());

				// set ICMP header fields
				icmp.setIcmpType((byte) 3);
				icmp.setIcmpCode((byte) 3);

				// extract etherPacket payload and format into ICMP payload
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] padding = new byte[4];
				try {
					baos.write(padding);
					baos.write(ethPayload.serialize());
				} catch (IOException e) {
					e.printStackTrace();
				}

				// convert to proper size and set data
				byte[] fullPayload = baos.toByteArray();
				byte[] partialPayload = new byte[4 + (ethPayload.getHeaderLength()*4) + 8];
				for (int i = 0; i < partialPayload.length; i++) {
					partialPayload[i] = fullPayload[i];
				}
				data.setData(partialPayload);

				this.sendPacket(ether, inIface);
				return;
			} 

			// echo reply
			else if (etherPacket.getEtherType() == IPv4.PROTOCOL_ICMP) {

				// set up pack headers
				Ethernet ether = new Ethernet();
				IPv4 ip = new IPv4();
				ICMP icmp = new ICMP();
				Data data = new Data();
				ether.setPayload(ip);
				ip.setPayload(icmp);
				icmp.setPayload(data);
				
				// set ether packet header fields
				ether.setEtherType(Ethernet.TYPE_IPv4);
				ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

				IPv4 ethPayload = (IPv4)etherPacket.getPayload();

				int macSRC = ethPayload.getSourceAddress();

				// Find matching route table entry 
				RouteEntry prev = this.routeTable.lookup(macSRC);
				
				int nextHop = prev.getGatewayAddress();
				if (0 == nextHop)
				{ nextHop = macSRC; }

				// Set destination MAC address in Ethernet header
				ArpEntry arpEntry = this.arpCache.lookup(nextHop);
				ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

				// set IP header fields
				ip.setTtl((byte) 64);
				ip.setProtocol(IPv4.PROTOCOL_ICMP);
				ip.setSourceAddress(ethPayload.getDestinationAddress());
				ip.setDestinationAddress(ethPayload.getSourceAddress());

				// set ICMP header fields
				icmp.setIcmpType((byte) 0);
				icmp.setIcmpCode((byte) 0);

				// extract etherPacket payload and format into ICMP payload
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] padding = new byte[4];
				try {
					baos.write(padding);
					baos.write(ethPayload.serialize());
				} catch (IOException e) {
					e.printStackTrace();
				}

				// set data
				byte[] fullPayload = baos.toByteArray();
				data.setData(fullPayload);
				
				this.sendPacket(ether, inIface);
				return;
			}
			
			return; 
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{ 
			// set up pack headers
			Ethernet ether = new Ethernet();
			IPv4 ip = new IPv4();
			ICMP icmp = new ICMP();
			Data data = new Data();
			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);

			// set ether packet header fields
			ether.setEtherType(Ethernet.TYPE_IPv4);
			ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

			IPv4 ethPayload = (IPv4)etherPacket.getPayload();

			int macSRC = ethPayload.getSourceAddress();

			// Find matching route table entry 
			RouteEntry prev = this.routeTable.lookup(macSRC);

			int nextHop1 = prev.getGatewayAddress();
			if (0 == nextHop1)
			{ nextHop1 = macSRC; }

			// Set destination MAC address in Ethernet header
			ArpEntry arpEntry1 = this.arpCache.lookup(nextHop1);
			ether.setDestinationMACAddress(arpEntry1.getMac().toBytes());

			// set IP header fields
			ip.setTtl((byte) 64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(inIface.getIpAddress());
			ip.setDestinationAddress(ethPayload.getSourceAddress());

			// set ICMP header fields
			icmp.setIcmpType((byte) 3);
			icmp.setIcmpCode((byte) 1);

			// extract etherPacket payload and format into ICMP payload
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] padding = new byte[4];
			try {
				baos.write(padding);
				baos.write(ethPayload.serialize());
			} catch (IOException e) {
				e.printStackTrace();
			}

			// convert to proper size and set data
			byte[] fullPayload = baos.toByteArray();
			byte[] partialPayload = new byte[4 + (ethPayload.getHeaderLength()*4) + 8];
			for (int i = 0; i < partialPayload.length; i++) {
				partialPayload[i] = fullPayload[i];
			}
			data.setData(partialPayload);

			this.sendPacket(ether, inIface);
			return; 
		}

		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}
}
