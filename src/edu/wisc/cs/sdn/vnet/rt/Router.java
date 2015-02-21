package edu.wisc.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host
	 *            hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile
	 *            the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
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
	 * 
	 * @param arpCacheFile
	 *            the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket
	 *            the Ethernet packet that was received
	 * @param inIface
	 *            the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: "
				+ etherPacket.toString().replace("\n", "\n\t"));

		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("IPv4 check fail");
			return;
		}


		IPv4 packet = (IPv4) etherPacket.getPayload();
		short checksum = packet.getChecksum();
		byte ttl = packet.getTtl();
		packet.setChecksum((short) 0);
		byte[] dPacket = packet.serialize();
		packet = (IPv4) packet.deserialize(dPacket, 0, dPacket.length);
		if (packet.getChecksum() != checksum || ttl <= 1) {
			System.out.println("checkum/ttl fail " + checksum + " " + ttl);
			return;
		}
		ttl -= 1;
		packet.setTtl(ttl);
		packet.setChecksum((short) 0);
		dPacket = packet.serialize();
		packet = (IPv4) packet.deserialize(dPacket, 0, dPacket.length);
		etherPacket.setPayload(packet);

		for (Iface iface : interfaces.values()) {
			if (iface.getIpAddress() == packet.getDestinationAddress()) {
				System.out.println("Router Interface drop");
				return;
			}
		}

		RouteEntry entry = routeTable.lookup(packet.getDestinationAddress());
		if (entry == null) {
			System.out.println("Route Table lookup fail");
			return;
		}

		ArpEntry lookup = arpCache.lookup(packet.getDestinationAddress());
		if (lookup == null) {
			System.out.println("Arp fail");
			return;
		}

		etherPacket.setDestinationMACAddress(lookup.getMac().toBytes());
		etherPacket.setSourceMACAddress(entry.getInterface().getMacAddress()
				.toBytes());

		sendPacket(etherPacket, entry.getInterface());
	}
}
