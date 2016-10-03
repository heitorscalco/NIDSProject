package preprocessor;
import java.util.HashMap;

//Tested in April 18 with Linux Ubuntu 14.04 LTS + Eclipse Mars 4.5.0 + Java 8 
//Tested in May 24 with Windows 10 Home + Eclipse Mars 4.5.0 + Java 7

public class Config {
	
	/**
	 * Method to capture packets.
	 * ONLINE = TRUE (if ONLINE = TRUE, you can set ENABLE_SOCKET to communicate with the classification engine)
	 * OFFLINE = FALSE
	 */
	public static boolean CAPTURE_ONLINE = true;
	public static boolean ENABLE_SOCKET = true;
		/**
		 * SOCKET PARAMETERS
		 * host_address = Destination host address
		 * dest_port = 59000 default
		 */
		public static final String host_address =  "192.168.1.28";
		public static final int dest_port =  59001;
		 
	public static final String PATH_TO_OFFLINE_PCAP = "D:\\ISCX 2012 - Copia\\testbed-17jun.pcap";
	
	/**
	 * This parameter sets how may threads will remove the packets of buffer.
	 * Recommended: NUM_THREADS_OF_BUFFER = Number of CPU cores.
	 */
	public static final int NUM_THREADS_OF_BUFFER = 4;
	
	/**
	 * This parameter sets how many packets will be in buffer.
	 * Case the Num. of packets exceeds the TAM_PACKET_BUFFER the buffer will be clean.
	 */
	public static int TAM_PACKET_BUFFER = 10000; //Number of PCs in network * 10000	
	public static int LIMIT_BUFFER = 20000;
	
	/**
	 * Moving average parameters: 
	 * @WINDOW_MOVING_AVERAGE: How many samples will be used to calculate Moving Average.
	 * @INTERVAL_TO_ANALYSE_MOVING_AVERAGE: The interval that the samples will be collected.
	 */
	public static final boolean USE_MOVING_AVERAGE = false;
		public static final int WINDOW_MOVING_AVERAGE = 10; 
		public static final int INTERVAL_TO_ANALYSE_MOVING_AVERAGE = 20000; //in milliseconds
		
	/**
	 * This parameter sets the PATH to save the dataset. 	
	 */
	public static final String PATH_TO_OUTPUT = "C:\\saida_base_de_dados.txt";
		
	/**
	 * If you have a labeled dataset:
	 * The @CONNECTIONS_LABELED will save the status of each connection, if it is Normal or Attack.
	 * Examples:
	 * 192.168.1.101;tcp_ip;4058;192.168.1.103;139;17/06/2010 23:58;17/06/2010 23:58;Normal
	 * 192.168.3.117;tcp_ip;2549;142.176.121.93;80;17/06/2010 23:58;17/06/2010 23:58;Normal
	 * 192.168.1.102;udp_ip;138;192.168.1.255;138;17/06/2010 23:58;17/06/2010 23:58;Attack  
	 */
	public static final boolean INCLUDE_LABELS_FILE = false; 
		public static final String PATH_LABELS_FILE = "C:\\labels.txt";
		public static final HashMap<String, String> CONNECTIONS_LABELED = new HashMap<String,String>();	
	
	/**
	 * Sniffer parameters: 
	 * @INTERFACE_TO_SNIFF
	 * @FILTER
	 */
	public static final String INTERFACE_TO_SNIFF = "Realtek PCIe FE Family Controller";
//	public static final String FILTER = "ip and (tcp or udp or icmp) or arp and (not host 127.0.0.1)";
	public static final String FILTER = "ip and (tcp or udp or icmp) or arp";
	
	/**
	 * Sets the length of time buffer and connections buffer 
	 */
	public static final int TIME = 2;  			//How many seconds in the past to analyse
	public static final int TAM_BUFFER = 100;	//How many connections in the past to analyse

	/**
	 * Layout of Output
	 * Example: 0.0,tcp,30,40,50,60,[...],Attack;
	 * @SEPARATOR is the divisor between the attributes;
	 * @TERMINATOR is the end character;
	 * @INCLUDE_LABELS yes/no to include the labels of each connection (Normal or Attack), generally in Online mode the parameter is false; 
	 */
	public static final String SEPARATOR = ",";
	public static final String TERMINATOR = ";";
	public static final boolean INCLUDE_LABELS = false;

	/**
	 * TAGS of types of classification and protocols
	 */
	public static final String TAG_DEFAULT = "normal";
	public static final String TAG_NORMAL = "normal";
	public static final String TAG_ATTACK = "ataque";
	public static final String TAG_ICMP = "ICMP";
	public static final String TAG_TCP = "TCP";
	public static final String TAG_UDP = "UDP";
	public static final String TAG_ARP = "ARP";
	public static final String TAG_SourceToDest = "SourceToDest";
	public static final String TAG_DestToSource = "DestToSource";
	
	
	/**
	 * States of Connection
	 * How the ARP, ICMP and UDP connections has not connection status, it was defined like Unknown;
	 * Of course it can be changed (not recommended). 
	 */	
	public static final String FLAG_ARP = "Unknown";
	public static final String FLAG_ICMP = "Unknown";
	public static final String FLAG_UDP = "Unknown";
		
	
	/**
	 * Timeouts as defined in "Reinforcing Network Security by Converting Massive Data Flow to Continuous Connections for IDS - Maher Salem et al"
	 */
//	public static final int TIMEOUT_DONT_ANALYSE = 720;
//	public static final int TIMEOUT_TCP_HANDSHAKE = 20;
//	public static final int TIMEOUT_TCP_ESTABLISHED = 720;
//	public static final int TIMEOUT_TCP_TERMINATION = 675;
//	public static final int TIMEOUT_TCP_CLOSED = 240;
//	public static final int TIMEOUT_OTHER = 60;
//	public static final int TIMEOUT_UDP = 180;
//	public static final int TIMEOUT_ICMP = 180;
//	public static final int TIMEOUT_ARP = 10;
	public static final int TIMEOUT_DONT_ANALYSE = 1;
	public static final int TIMEOUT_TCP_HANDSHAKE = 1;
	public static final int TIMEOUT_TCP_ESTABLISHED = 1;
	public static final int TIMEOUT_TCP_TERMINATION = 1;
	public static final int TIMEOUT_TCP_CLOSED = 1;
	public static final int TIMEOUT_OTHER = 1;
	public static final int TIMEOUT_UDP = 1;
	public static final int TIMEOUT_ICMP = 1;
	public static final int TIMEOUT_ARP = 1;	
	
	
	/**
	 * The CURRENT_TIMESTAMP_TO_COMPARE parameter was created to compare the timeouts;
	 * If @param equals TRUE, so the current time will be compared to know if the connection was timeouted or not.
	 * Otherwise, if @param equals FALSE, so the time of the last packet will be compared.
	 * The @param equals FALSE is generally used to simulate networks reproducing pcap files with tcpreplay (per example). In this situation, the timestamp of the packets are too old and its not 
	 * possible to compare with the current timestamp (of the system).  
	 */
	public static boolean CURRENT_TIMESTAMP_TO_COMPARE = false; 
		
	/**
	 * The list of possible services.
	 */
	public static final HashMap<Integer, String> services = new HashMap<Integer, String>();
	static{
		services.put(17600, "DROPBOX");
		services.put(17603, "DROPBOX");
		services.put(17500, "DROPBOX");
		
		services.put(22, "SSH");
		services.put(67, "DHCP");
		services.put(68, "DHCP");

		services.put(25, "SMTP");
		services.put(2525, "SMTP");
		services.put(587, "SMTP");

		services.put(143, "IMAP4");
		services.put(993, "IMAP4");

		services.put(137, "NETBIOS");
		services.put(138, "NETBIOS");
		services.put(139, "NETBIOS");

		services.put(53, "DNS");
		services.put(70, "GOPHER");
		services.put(7, "ECHO");
		services.put(515, "PRINTER");
		services.put(111, "SUNRPC");
		services.put(20, "FTP-DATA");
		services.put(21, "FTP");

		services.put(540, "UUCP");
		services.put(541, "UUCP");

		services.put(109, "POP2");
		services.put(110, "POP3");
		services.put(11, "SYSTAT");
		services.put(43, "WHOIS");

		services.put(71, "REMOTE_JOB");
		services.put(72, "REMOTE_JOB");
		services.put(73, "REMOTE_JOB");
		services.put(74, "REMOTE_JOB");

		services.put(150, "SQL_NET");
		services.put(13, "DAYTIME");

		services.put(520, "EFS");
		services.put(556, "EFS");

		services.put(123, "NTP_U");
		services.put(119, "NNTP");
		services.put(443, "HTTPS");
		services.put(80, "HTTP");
		services.put(8080, "HTTP");
		services.put(15, "NETSTAT");

		services.put(23, "TELNET");
		services.put(89, "TELNET");
		services.put(107, "TELNET");
		services.put(513, "TELNET");

		services.put(37, "TIME");
		services.put(175, "VMNET");
		services.put(543, "KLOGIN");
		services.put(69, "TFTP_U");
		services.put(57, "MTP");
		services.put(179, "BGP");
		services.put(433, "NNSP");
		services.put(84, "CTF");
		services.put(9, "DISCARD");
		services.put(49, "LOGIN");
		services.put(95, "SUPDUP");
		services.put(194, "IRC");
		services.put(6000, "X11");
		services.put(6001, "X11");
		services.put(6063, "X11");

		services.put(105, "CSNET_NS");
		services.put(245, "LINK");
		services.put(113, "AUTH");
		services.put(5, "REJ");
		services.put(544, "KSHELL");
		services.put(562, "SHELL");
		services.put(117, "UUCP_PATH");
		services.put(530, "COURIER");
		services.put(512, "EXEC");
		services.put(389, "LDAP");
		services.put(102, "ISO_TSAP");
		services.put(79, "FINGER");

		services.put(24, "PRIVATE");
		services.put(35, "PRIVATE");
		services.put(59, "PRIVATE");
		services.put(75, "PRIVATE");
		services.put(77, "PRIVATE");
		services.put(87, "PRIVATE");

		services.put(387, "URP_I");
		services.put(210, "Z39_50");
		services.put(5355, "LLMNR");
		services.put(4070, "SPOTIFY");

		services.put(4244, "VOIP");
		services.put(5222, "VOIP");
		services.put(5223, "VOIP");
		services.put(5224, "VOIP");
		services.put(5228, "VOIP");
		services.put(5229, "VOIP");
		services.put(5242, "VOIP");
		services.put(5269, "VOIP");	
		services.put(19302, "VOIP");
		services.put(19303, "VOIP");
		services.put(19304, "VOIP");
		services.put(19305, "VOIP");
		services.put(19306, "VOIP");
		services.put(19307, "VOIP");
		services.put(19308, "VOIP");
		services.put(19309, "VOIP");
		services.put(23259, "VOIP");
		
		services.put(5938, "VNC");
		services.put(5800, "VNC");
		services.put(5801, "VNC");
		services.put(5802, "VNC");
		services.put(5803, "VNC");
		services.put(5900, "VNC");
		services.put(5901, "VNC");
		services.put(5902, "VNC");
		services.put(5903, "VNC");
		services.put(6000, "VNC");
		services.put(6001, "VNC");
		
		services.put(1900, "SSDP");
	}	
}		