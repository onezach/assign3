package edu.wisc.cs.sdn.vnet.rt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device implements Runnable
{	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** thread to send unsolicited response messages */
	private Thread ripResponseSender;

	private Thread timeout;

	/** RIP Table for the router */
	private Map<RIPv2Entry, Long> ripTable;

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
		this.ripResponseSender = new Thread(this);
		this.ripTable = new HashMap<RIPv2Entry, Long>();
		this.timeout = new Thread(new ThreadTimeOut(ripTable, routeTable));
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

	public void printRip(Map<RIPv2Entry, Long> ripTable) {
		for (Map.Entry<RIPv2Entry, Long> entry : ripTable.entrySet()) {
			System.out.println("address = " + entry.getKey().getAddress() + " subnet mask = " + entry.getKey().getSubnetMask() + " metric = " + entry.getKey().getMetric());
		}
	}

	public void startRip() {
		synchronized(ripTable) {
			synchronized(routeTable){
		// initalize routeTable and ripTable
		for (Iface curIFace: interfaces.values()) {
			// create router entry
			int ip = curIFace.getIpAddress();
			int mask = curIFace.getSubnetMask();
			routeTable.insert(ip, 0, mask, curIFace);

			// create ripTable entry
			RIPv2Entry entry = new RIPv2Entry(ip, mask, 1);
			ripTable.put(entry, System.currentTimeMillis());
		}
	}
}

		System.out.println(routeTable);

		// send out rip requests to all neighbors
		for (Iface curIface: interfaces.values()) {
			// create all packet headers
			Ethernet ether = new Ethernet();
			IPv4 ip = new IPv4();
			UDP udp = new UDP();
			RIPv2 ripPacket = new RIPv2();
			
			// set ether headers
			byte[] broadcast = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}; //DestMac set to all ones
			ether.setDestinationMACAddress(broadcast);
			ether.setSourceMACAddress(curIface.getMacAddress().toBytes());
			ether.setEtherType(Ethernet.TYPE_IPv4);
			ether.setPayload(ip);

			// set ip headers
			ip.setDestinationAddress(-536870903); //int version of 224.0.0.9 Special multi cast for RIP
			ip.setSourceAddress(curIface.getIpAddress());
			ip.setProtocol(IPv4.PROTOCOL_UDP);
			ip.setTtl((byte)64);
			ip.setPayload(udp);

			//set udp headers
			udp.setDestinationPort(UDP.RIP_PORT);
			udp.setSourcePort(UDP.RIP_PORT);
			udp.setPayload(ripPacket);

			//set rip packet
			ripPacket.setEntries(new LinkedList<RIPv2Entry>(ripTable.keySet()));
			ripPacket.setCommand(RIPv2.COMMAND_REQUEST);

			// send the packet
			this.sendPacket(ether, curIface);


		}
		ripResponseSender.start();
		timeout.start();
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
			{ 
				// System.out.println("Match");
				// System.out.println("etherType:" + etherPacket.getEtherType() + " U/T:" + IPv4.PROTOCOL_UDP + "/" + IPv4.PROTOCOL_TCP);
				IPv4 ethPayload = (IPv4)etherPacket.getPayload();
				if (ethPayload.getProtocol() == IPv4.PROTOCOL_UDP || ethPayload.getProtocol() == IPv4.PROTOCOL_TCP) {

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
	
					// IPv4 ethPayload = (IPv4)etherPacket.getPayload();
	
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
				else if (ethPayload.getProtocol() == IPv4.PROTOCOL_ICMP) {
	
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
	
					// IPv4 ethPayload = (IPv4)etherPacket.getPayload();
	
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
		}

				//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		//                                                        RIP Code
		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
			UDP udpPacket = (UDP)ipPacket.getPayload();

			// check for correct port (520)
			if (udpPacket.getDestinationPort() == UDP.RIP_PORT && udpPacket.getSourcePort() == UDP.RIP_PORT) {
				RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();

				// handle request command
				if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
					// create all packet headers
					Ethernet ether = new Ethernet();
					IPv4 ip = new IPv4();
					UDP udp = new UDP();
					RIPv2 ripPacketNew = new RIPv2();
					
					// IPv4 ethPayload = (IPv4)etherPacket.getPayload();

					// int macSRC = ipPacket.getSourceAddress();

					// // Find matching route table entry 
					// RouteEntry prev = this.routeTable.lookup(macSRC);
					
					// int nextHop = prev.getGatewayAddress();
					// if (0 == nextHop)
					// { nextHop = macSRC; }

					// // Set destination MAC address in Ethernet header
					// ArpEntry arpEntry = this.arpCache.lookup(nextHop);
					// ether.setDestinationMACAddress(arpEntry.getMac().toBytes());


					// set ether headers
					ether.setDestinationMACAddress(etherPacket.getSourceMACAddress()); // set to source mac of recieved packet. Ask Zach does this need to be done like it as above with Arp Cache
					ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
					ether.setEtherType(Ethernet.TYPE_IPv4);
					ether.setPayload(ip);

					// set ip headers
					ip.setDestinationAddress(ipPacket.getSourceAddress());
					ip.setSourceAddress(inIface.getIpAddress());
					ip.setProtocol(IPv4.PROTOCOL_UDP);
					ip.setTtl((byte)64);
					ip.setPayload(udp);

					//set udp headers
					udp.setDestinationPort(UDP.RIP_PORT);
					udp.setSourcePort(UDP.RIP_PORT);
					udp.setPayload(ripPacket);

					//set rip packet
					ripPacketNew.setEntries(new LinkedList<RIPv2Entry>(ripTable.keySet()));
					ripPacketNew.setCommand(RIPv2.COMMAND_RESPONSE);

					// send the packet
					this.sendPacket(ether, inIface);

				}
				else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) {
					synchronized(ripTable){
						synchronized(routeTable){
					// potentially update routeTable and ripTable based on new information from ripPacket
					for (RIPv2Entry entry : ripPacket.getEntries()) {
						// add to route table and rip table if doesn't exist
						// System.out.println("----------------entry" + entry.getAddress());
						// System.out.println("----------------iface" + inIface.getIpAddress());
						if (routeTable.lookup(entry.getAddress()) == null && entry.getAddress() != inIface.getIpAddress()) { //should this be "entry.getAddress() & entry.getMask()"
							routeTable.insert(entry.getAddress(), ipPacket.getSourceAddress(), entry.getSubnetMask(), inIface); // go over with zach
							RIPv2Entry newRip = new RIPv2Entry(entry.getAddress(), entry.getSubnetMask(), entry.getMetric() + 1);
							ripTable.put(newRip, System.currentTimeMillis());
						}
					}

					// Iterator<Map.Entry<RIPv2Entry, Long>> iter = ripTable.entrySet().iterator();
					// while (iter.hasNext()) {
					// 	Map.Entry<RIPv2Entry, Long> entry = iter.next();

					// 	if (System.currentTimeMillis() - entry.getValue() > 30000) {
					// 		routeTable.remove(entry.getKey().getAddress(), entry.getKey().getSubnetMask());
					// 		iter.remove();
					// 		System.out.println("removed " + entry.getKey().getAddress());
					// 		System.out.println(routeTable);
							
					// 	}
					// }

					// check recived packets rip to see if need to update any entries
					for (RIPv2Entry potentiallyBetterRIPEntry : ripPacket.getEntries()) {
						// for (RIPv2Entry currentRipEntry : ripTable.keySet()) {
						Iterator<RIPv2Entry> iter = ripTable.keySet().iterator();
						ArrayList<RIPv2Entry> toAdd = new ArrayList<RIPv2Entry>();
						while (iter.hasNext()) {
							RIPv2Entry currentRipEntry = iter.next();

							if (potentiallyBetterRIPEntry.getAddress() == currentRipEntry.getAddress()
								&& potentiallyBetterRIPEntry.getSubnetMask() == currentRipEntry.getSubnetMask()) {
								// update time
								ripTable.replace(currentRipEntry, System.currentTimeMillis());
								if (potentiallyBetterRIPEntry.getMetric() < currentRipEntry.getMetric() - 1) {
									// update current rip table and routing table
									
									// ripTable.remove(currentRipEntry);
									RIPv2Entry newRip = new RIPv2Entry(potentiallyBetterRIPEntry.getAddress(), potentiallyBetterRIPEntry.getSubnetMask(), potentiallyBetterRIPEntry.getMetric() + 1);
									// ripTable.put(newRip, System.currentTimeMillis());
									toAdd.add(newRip);
									routeTable.remove(currentRipEntry.getAddress(), currentRipEntry.getSubnetMask());
									routeTable.insert(currentRipEntry.getAddress(), ipPacket.getSourceAddress(), currentRipEntry.getSubnetMask(), inIface);
									iter.remove();
								}
							}
						}
						for (RIPv2Entry newRip : toAdd) {
							ripTable.put(newRip, System.currentTimeMillis());
						}
					}
				}
			}

					System.out.println(routeTable);
					printRip((ripTable));
				}

				return;
			}
		}
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
		{ return; }

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

	@Override
	public void run() {
		while (true)
		{
			// Run every 10 seconds
			try 
			{ Thread.sleep(10000); }
			catch (InterruptedException e) 
			{ break; }

			// send out unsolocited rip responses to all neighbors
			for (Iface curIface: interfaces.values()) {
				// create all packet headers
				Ethernet ether = new Ethernet();
				IPv4 ip = new IPv4();
				UDP udp = new UDP();
				RIPv2 ripPacket = new RIPv2();
				
				// set ether headers
				byte[] broadcast = {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}; //DestMac set to all ones
				ether.setDestinationMACAddress(broadcast);
				ether.setSourceMACAddress(curIface.getMacAddress().toBytes());
				ether.setEtherType(Ethernet.TYPE_IPv4);
				ether.setPayload(ip);

				// set ip headers
				ip.setDestinationAddress(-536870903); //int version of 224.0.0.9 Special multi cast for RIP
				ip.setSourceAddress(curIface.getIpAddress());
				ip.setProtocol(IPv4.PROTOCOL_UDP);
				ip.setTtl((byte)64);
				ip.setPayload(udp);

				//set udp headers
				udp.setDestinationPort(UDP.RIP_PORT);
				udp.setSourcePort(UDP.RIP_PORT);
				udp.setPayload(ripPacket);

				//set rip packet
				synchronized(routeTable){
				ripPacket.setEntries(new LinkedList<RIPv2Entry>(ripTable.keySet()));
				}
				ripPacket.setCommand(RIPv2.COMMAND_RESPONSE);

				// send the packet
				this.sendPacket(ether, curIface);

			}
			
			
		}
		
	}
}

class ThreadTimeOut implements Runnable {

	private Map<RIPv2Entry, Long> ripTable;
	private RouteTable routeTable;

	public ThreadTimeOut(Map<RIPv2Entry, Long> table, RouteTable routeTable) {
		this.ripTable = table;
		this.routeTable = routeTable;
	}
		

	@Override
	public void run() {
		while (true)
		{
			try 
				{ Thread.sleep(5000); }
				catch (InterruptedException e) 
				{ break; }


			synchronized(ripTable){
				synchronized(routeTable){
					Iterator<Map.Entry<RIPv2Entry, Long>> iter = ripTable.entrySet().iterator();
					while (iter.hasNext()) {
						Map.Entry<RIPv2Entry, Long> entry = iter.next();

						if (System.currentTimeMillis() - entry.getValue() > 30000) {
							routeTable.remove(entry.getKey().getAddress(), entry.getKey().getSubnetMask());
							iter.remove();
							System.out.println("removed " + entry.getKey().getAddress());
							System.out.println(routeTable);
							
						}
					}
				}
			}
		}
	}
}
