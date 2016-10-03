package capturator;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;  
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.sun.corba.se.impl.orbutil.concurrent.Mutex;

import capturator.Packet;
import manager.ConnectionsManager;

import org.jnetpcap.packet.format.FormatUtils;

import preprocessor.Config;


public class Capture {					
	
	public static ArrayList<Packet> packet_buffer = new ArrayList<Packet>();
	public static Mutex mutex = new Mutex();
	public static Mutex mutex_packet_buffer = new Mutex();
	public static long num_pkts = 0;
	
	private static void printFrameworkParameters() {
				
		System.out.println("###################################################");
		System.out.println("\n               CAPTURE PARAMETERS                  \n");
		
		if(Config.CAPTURE_ONLINE == true){
			System.out.println("Capture Mode: ONLINE" );
		} else {
			System.out.println("Capture Mode: OFFLINE with FILE: " + Config.PATH_TO_OFFLINE_PCAP );
		}
		
		System.out.println("Network Interface: " + Config.INTERFACE_TO_SNIFF);
		System.out.println("Sniffer Filter: " + Config.FILTER);		
		
		System.out.println("\n               BUFFER PARAMETERS                  \n");
		System.out.println("Length of TIME BUFFER: " + Config.TIME);
		System.out.println("Length of CONNECTION BUFFER: " + Config.TAM_BUFFER);
		
		
		System.out.println("\n               FRAMEWORK PARAMETERS               \n");
		System.out.println("Default Output Classification: " + Config.TAG_DEFAULT);				
		
		System.out.println("Number of threads for Packet Buffer: " + Config.NUM_THREADS_OF_BUFFER);
		System.out.println("Initial Length of Packet Buffer: " + Config.TAM_PACKET_BUFFER);
		System.out.println("Maximum Length of Connections Buffer: " + Config.LIMIT_BUFFER);
		if(Config.USE_MOVING_AVERAGE){
			System.out.println("\nUsing Moving Average? Yes");
			System.out.println("Window Moving Average: " + Config.WINDOW_MOVING_AVERAGE);
			System.out.println("Time to update Window Moving Average: " + Config.INTERVAL_TO_ANALYSE_MOVING_AVERAGE);
			System.out.println("\n");
		}
		System.out.println("Path to save output dataset: " + Config.PATH_TO_OUTPUT);
		if(Config.INCLUDE_LABELS_FILE){
			System.out.println("Using Labels File? Yes");
			System.out.println("Path to Labels File: " + Config.PATH_LABELS_FILE);					
		}	
		System.out.println("\n###################################################\n\n");
	}
	
	private static boolean listLabelsOfConnections(){
		System.out.println("\n\nLOADING THE FILE THAT CONTAINS THE LABELS.");
		System.out.println("This may take some time, Please Wait. \n\n");
		try{
			FileReader arq = new FileReader(Config.PATH_LABELS_FILE);
			BufferedReader lerArq = new BufferedReader(arq);
			String linha = lerArq.readLine();
			String unique_id;
			while (linha != null) {															
				String[] words = linha.split(";");
				String datahora = words[5].split(":")[0];
				//{TIMESTAMP -- PROTOCOLO -- IP_ORIGEM:PORTA_ORIGEM -- IP_DEST:PORTA_DEST}		
				if(words[1].equals("tcp_ip")){
					unique_id = datahora + "--" + Config.TAG_TCP + "--" + words[0] + ":" + words[2] + "--" + words[3] + ":" + words[4];
				} else if (words[1].equals("udp_ip")) {
					unique_id = datahora + "--" + Config.TAG_UDP + "--" + words[0] + ":" + words[2] + "--" + words[3] + ":" + words[4];
				} else if (words[1].equals("icmp_ip") || words[1].equals("ipv6icmp")) {
					unique_id = datahora + "--" + Config.TAG_ICMP + "--" + words[0] + ":" + words[2] + "--" + words[3] + ":" + words[4];
				} else if (words[1].equals("ip") || words[1].equals("arp") || words[1].equals("igmp")) {
					unique_id = datahora + "--" + Config.TAG_ARP + "--" + words[0] + ":" + words[2] + "--" + words[3] + ":" + words[4];
				} else {
					continue;
				}																
				Config.CONNECTIONS_LABELED.put(unique_id, words[7]);
				
				linha = lerArq.readLine();
			}
			arq.close();
			System.out.println("File loaded successfully!!!");
			return(true);
		} catch(Exception ex){
			System.out.println("An error has ocurred, exiting now...");
			return(false);
		}
	}

	public static void main(String[] args){					
		try{
			System.loadLibrary("jnetpcap");	          
		}catch(Exception ex){
			ex.printStackTrace();
			return;
		}
		
		printFrameworkParameters();
		
		if(Config.INCLUDE_LABELS_FILE){
			if(listLabelsOfConnections() == false){
				return;
			}
		}						 		
						
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); 	// For any error msgs           
        Pcap pcap; 
        if(Config.CAPTURE_ONLINE == true){        	                       
	        Pcap.findAllDevs(alldevs, errbuf);  
	        
	        if (alldevs.isEmpty()) {
	            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());  
	            return;  
	        }  
	  
	        System.out.println("Network devices found:");    
	        int i = 0, if_aux = -1;
	        String if_aux_name = null, if_aux_description = null;
	        for (PcapIf device : alldevs) {        	
	            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
	            if((device.getName().matches(Config.INTERFACE_TO_SNIFF) == true) || (device.getDescription().matches(Config.INTERFACE_TO_SNIFF) == true)){
	            	if_aux = i;
	            	if_aux_name = device.getName();
	            	if_aux_description = device.getDescription();
	            }
	            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
	        }
	        
	        if(if_aux == -1){
	        	System.err.printf("Network device %s not found!\n", Config.INTERFACE_TO_SNIFF);
	        	return;        	
	        }       
	        
	                
	        PcapIf device = alldevs.get(if_aux);        
	                   
	        int snaplen = 64 * 1024;           // Capture all packets, no trucation
	        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	        int timeout = 10 * 1000;           // 10 seconds in millis
	        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
	        if (pcap == null) {  
	            System.err.printf("Error while opening device for capture: [Permission Error?] " + errbuf.toString());  
	            return;
	        }
	        
	        System.out.printf("\n\n***Listening on Interface: #%d: %s [%s]***\n", if_aux, if_aux_name, if_aux_description);
	        
        } else {
			//OFFLINE                    
			pcap = Pcap.openOffline(Config.PATH_TO_OFFLINE_PCAP, errbuf);			
			if (pcap == null) {  
				System.err.println(errbuf);  
				return;  
			}
        }
        
        PcapBpfProgram program = new PcapBpfProgram();
        int optimize = 1;         // 0 = false
        int netmask = 0xFFFF0000; // 255.255.0.0
        
        System.out.println("Filter: " + Config.FILTER+"\n");
        		
        if (pcap.compile(program, Config.FILTER, optimize, netmask) != Pcap.OK) {
          System.err.println(pcap.getErr());
          return;
        }
        		
        if (pcap.setFilter(program) != Pcap.OK) {
          System.err.println(pcap.getErr());
          return;		
        }
        
        ConnectionsManager gerenciador = new ConnectionsManager();
		gerenciador.startMonitoringThread(); //Start the monitor of buffer
		gerenciador.updateMovingAverage();
		for (int i = 0; i < Config.NUM_THREADS_OF_BUFFER; i++) {
			gerenciador.startManagerThread(); //Start the consumer of packets buffer
		}
		
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {    	    
        	Tcp tcp = new Tcp();  
            Udp udp = new Udp();
            Icmp icmp = new Icmp();
            Arp arp = new Arp();
            Ip4 ip = new Ip4();
           
        	public void nextPacket(PcapPacket packet, String user) {  	    		    	    		         		     
        		
        		Packet pkt = new Packet();
        		
        		if (packet.hasHeader(ip)){
        			pkt.setIPsrc(FormatUtils.ip(ip.source()));
		        	pkt.setIPdst(FormatUtils.ip(ip.destination()));		        	
		        	pkt.setTimestamp(new Date(packet.getCaptureHeader().timestampInMillis()));
		        	pkt.setIpID(ip.id());
		        	pkt.setTTL(ip.ttl());
		        			        	
		        	if(ip.checksum() == ip.calculateChecksum()){
			        	pkt.setWrong(0);
		        	} else {
			        	pkt.setWrong(1);
		        	}
		        	
		        	if (packet.hasHeader(tcp)){
						pkt.setProtocol(Config.TAG_TCP);			        	
			        	pkt.setSport(tcp.source());
			        	pkt.setDport(tcp.destination());
			        	pkt.setLength(tcp.getLength());			        				        

			        	//Flags
			        	pkt.setSYN(tcp.flags_SYN());
			        	pkt.setACK(tcp.flags_ACK());
			        	if(tcp.flags_SYN() == true && tcp.flags_ACK() == true){
			        		pkt.setSYNACK(true);
			        	}			        	
			        	pkt.setRST(tcp.flags_RST());
			        	pkt.setFIN(tcp.flags_FIN());
			        	pkt.setPSH(tcp.flags_PSH());
			        				        				        				        				        				    			        				        	
			        	if (tcp.flags_URG() == false) {
			        		pkt.setUrgptr(0);
			        	} else {
			        		pkt.setUrgptr(1);
			        	}			        				       
			        } else if(packet.hasHeader(udp)) {			        	
			        	pkt.setProtocol(Config.TAG_UDP);
			        	pkt.setSport(udp.source());
			        	pkt.setDport(udp.destination());
			        	pkt.setLength(udp.getLength());			        				        			        
			        } else if(packet.hasHeader(icmp)){			        	
			        	pkt.setProtocol(Config.TAG_ICMP);
			        	pkt.setLength(icmp.getLength());
			        	pkt.setIcmp_ID(Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(38))).replace(' ', '0') + String.format("%8s", Integer.toBinaryString(packet.getUByte(39))).replace(' ', '0')), 2));
			        	pkt.setIcmp_Message(Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(34))).replace(' ', '0')), 2));	        				        				        				        
			        } 
        		} else if (packet.hasHeader(arp)){
        			pkt.setProtocol(Config.TAG_ARP);
        			pkt.setLength(arp.getLength());
        			pkt.setIPdst(Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(38))).replace(' ', '0')),2) + "." +Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(39))).replace(' ', '0')),2) + "." + Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(40))).replace(' ', '0')),2) + "." + Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(41))).replace(' ', '0')),2));
        			pkt.setIPsrc(Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(28))).replace(' ', '0')),2) + "." + Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(29))).replace(' ', '0')),2) + "." + Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(30))).replace(' ', '0')),2) + "." + Integer.parseInt((String.format("%8s", Integer.toBinaryString(packet.getUByte(31))).replace(' ', '0')),2));
		        	pkt.setTimestamp(new Date(packet.getCaptureHeader().timestampInMillis()));        			
		        } else {
        			System.out.printf("Invalid IP Header.\n\n");
        			return;
        		}        		
        		
				packet_buffer.add(pkt);
				packet = null;
				pkt = null;
									
				try { Thread.sleep(1); } catch (InterruptedException e) { e.printStackTrace(); }
				num_pkts++;					        			        	
		    }     	        	       
		};
		
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");			
        pcap.close();
        
        try {
			Thread.sleep(200000);
		} catch (InterruptedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        ConnectionsManager.kill();
		System.out.println("\n\n\n\n\n\n\n\n\n NUMBER OF PKTS: "+num_pkts+" \n\n\n\n\n\n\n\n\n");
        
        System.exit(0);
	}	
} 