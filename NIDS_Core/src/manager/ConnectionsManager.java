package manager;
import preprocessor.Output;
import preprocessor.Config;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.concurrent.TimeUnit;

import com.sun.corba.se.impl.orbutil.concurrent.Mutex;

import capturator.Capture;
import capturator.Connection;
import capturator.Packet;

public class ConnectionsManager extends Thread {
	public static LinkedHashMap<String, Connection> conexoes = new LinkedHashMap<String, Connection>();
	private ArrayList<Integer> MovingAverage = new ArrayList<Integer>();
	public static boolean isrunning = true;		
	static Output saida = new Output();		
	public static Date last_timestamp = null;
	private Mutex mutex_last_timestamp_var = new Mutex();
	private Mutex mutex_connections = new Mutex();
	
	
	public void updateMovingAverage(){
		new Thread() {		
			public void run(){
				this.setPriority(NORM_PRIORITY);
				int length_packets, size_buffer;
				while(isrunning){			
					length_packets = 0;
					size_buffer = 0;					
					try {
						Capture.mutex_packet_buffer.acquire();
						length_packets=Capture.packet_buffer.size();
						Capture.mutex_packet_buffer.release();
						if(length_packets > 0){
							if(MovingAverage.size() > Config.WINDOW_MOVING_AVERAGE)
								MovingAverage.remove(0);												
							MovingAverage.add(length_packets);
							
							if(MovingAverage.size() >= Config.WINDOW_MOVING_AVERAGE){
								for (int i = 0; i < MovingAverage.size(); i++) {
									size_buffer += MovingAverage.get(i);
								}							
								Config.TAM_PACKET_BUFFER = (int) Math.round((size_buffer/MovingAverage.size()));
							}																																										
						}	
						Thread.sleep(Config.INTERVAL_TO_ANALYSE_MOVING_AVERAGE);							
					} catch (InterruptedException e) {
						System.out.println("Problem in UpdateMovingAverage thread.");
						System.out.println(e);
					}
				}
			}
		}.start();
	}
	
	public void startMonitoringThread(){
		new Thread() {		
			public void run(){
				this.setPriority(NORM_PRIORITY);				
				while(isrunning){					
					try {
//						System.out.println("Verifica Timeouts..");
						verifyTimeouts();
						System.gc();
						Thread.sleep(20000);
					} catch (InterruptedException e) {
						System.out.println("Problema na Thread monitoramento.");
						System.out.println(e);
					}
				}
			}
		}.start();
	}
	
	public void startManagerThread(){
		//Remove the packets of the buffer to analysis.
		
		new Thread() {						
			public void run(){					
				Packet pkt = null;
				this.setPriority(MAX_PRIORITY);
				while(isrunning){
					pkt = null;
//					System.out.println(" Qtd. em Buffer: " + Captura.packet_buffer.size());
					try {
						Capture.mutex_packet_buffer.acquire();
						if(Capture.packet_buffer.isEmpty() == false){
							pkt = Capture.packet_buffer.get(0);							
							Capture.packet_buffer.remove(0);
						}
						Capture.mutex_packet_buffer.release();
					} catch (InterruptedException e1) {
						System.out.println("Problema no acquire 1 funcao managerthread");
					}
					if(pkt != null){
						synchronized (pkt) {						
							try {																			        	
					        	mutex_last_timestamp_var.acquire();
				        		last_timestamp = pkt.getTimestamp();
				        		mutex_last_timestamp_var.release();        	
								manageConnection(pkt);
							} catch (InterruptedException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
					}											
					try { Thread.sleep(1); } catch (InterruptedException e) {}					
				}							
			}
		}.start();
	}
	
	public static void startOutputThread(final Connection conexao){
		new Thread() {			
			public void run(){
				this.setPriority(NORM_PRIORITY);
				try {
					try {
//						System.out.println("Saída..");
						saida.outputTreatment(conexao);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} catch (IOException e) {
					System.err.println("Nao foi possÃ­vel despachar a conexao -  %s" + conexao.getUnique_id());
					e.printStackTrace();
				}				
			}
		}.start();
	}
	
	public static void kill(){
		isrunning = false;
	}
	
	@SuppressWarnings({"rawtypes"})
	public static void setTimeoutToALL() throws InterruptedException{
	    Iterator<?> it;
	    synchronized (conexoes) {
	    	Set<?> set = conexoes.entrySet();    	
		    it = set.iterator();	
	    }
	    Connection conexao_aux = null;
	    try{  		    		    
			while(it.hasNext()) {
				try {
					Map.Entry me = (Map.Entry)it.next();
					synchronized (conexoes) {
						conexao_aux = conexoes.get(me.getKey());
					}
					startOutputThread(conexao_aux);
				} catch (Exception e) {
					System.out.println("ERROR - while, setTimeoutToALL");
				}
							    	
			}				
	    } catch (Exception e) {	
	    	System.out.println("Error in Function SetTimeoutToALL");
			System.out.println(e);
		}	    
	    
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void verifyTimeouts() throws InterruptedException{		
	    GregorianCalendar data = new GregorianCalendar();
	    mutex_last_timestamp_var.acquire();					
	    if((Config.CURRENT_TIMESTAMP_TO_COMPARE == false) && (last_timestamp != null)){
	    	data.setTime(last_timestamp);
	    } 	    	    					    
	    mutex_last_timestamp_var.release();
	    
	    long diferenca = 0;
	 
	    LinkedHashMap<String, Connection> conexao_aux = new LinkedHashMap<String,Connection>();
	    Iterator<?> it;
	    synchronized (conexoes) {
	    	conexao_aux = (LinkedHashMap<String, Connection>) conexoes.clone();
	    	Set<?> set = conexao_aux.entrySet();    	
		    it = set.iterator();
		}	    	    	   

	    try{  		    		    
			while(it.hasNext()) {					
				Map.Entry me = (Map.Entry)it.next();				
		    	if(conexao_aux.get(me.getKey()).getTimeouted() == false){
	    			diferenca = TimeUnit.MILLISECONDS.toSeconds((data.getTimeInMillis() - conexao_aux.get(me.getKey()).getUltimoTS().getTime()));
	    			if(diferenca > conexao_aux.get(me.getKey()).getTimeout()){
						conexao_aux.get(me.getKey()).setTimeouted(true);						
						/**
						 * Despacha a Conexão para ser tratada e enviada para as técnicas de I.A
						 */						
						Connection conexao = conexao_aux.get(me.getKey());
						startOutputThread(conexao);	
						synchronized (conexoes) {
							conexoes.remove(me.getKey());
						}						
					} 
		    	}
			}				
	    } catch (Exception e) {	
	    	System.out.println("Error in Function VerifyTimeout");
			System.out.println(e);
		}	    
	}
	
	private void manageConnection(Packet pkt) throws InterruptedException{
		String unique_id, reverse_unique_id;
		boolean status_unique = false, status_reverse_unique = false;			
		
		try{
			if(pkt.getProtocol().equals(Config.TAG_ICMP)){			
				unique_id = pkt.getProtocol() + "_" + pkt.getIPsrc()+"-"+pkt.getIPdst()+"_"+pkt.getIcmp_ID();
				reverse_unique_id = pkt.getProtocol() + "_" + pkt.getIPdst()+"-"+pkt.getIPsrc()+"_"+pkt.getIcmp_ID();
			} else if (pkt.getProtocol().equals(Config.TAG_ARP)) {
				unique_id = pkt.getProtocol() + "_" + pkt.getIPsrc()+"-"+pkt.getIPdst();
				reverse_unique_id = pkt.getProtocol() + "_" + pkt.getIPdst()+"-"+pkt.getIPsrc();
			} else {
				unique_id = pkt.getProtocol() + "_" + pkt.getIPsrc()+":"+pkt.getSport()+"-"+pkt.getIPdst()+":"+pkt.getDport();
				reverse_unique_id = pkt.getProtocol() + "_" + pkt.getIPdst()+":"+pkt.getDport()+"-"+pkt.getIPsrc()+":"+pkt.getSport();
			}												
			
			mutex_connections.acquire();
			synchronized (conexoes) {
				status_unique = conexoes.containsKey(unique_id);
				status_reverse_unique = conexoes.containsKey(reverse_unique_id);			
			}
			mutex_connections.release();
			
			
			if(status_unique){				
				addPktInConnection(pkt, unique_id);
//				System.out.println("add: "+unique_id);
			} else if (status_reverse_unique){
				addPktInConnection(pkt, reverse_unique_id);
//				System.out.println("Add reverse: "+reverse_unique_id);
			} else {
				mutex_connections.acquire();
				createConnection(pkt, unique_id);
				mutex_connections.release();
//				System.out.println("New Connection: "+unique_id);
			}							
			pkt = null;
		} catch (Exception e) {
			System.err.println("Some problem with the packet.");
			System.out.println(e);
		}

	}
	
	private Connection updateConnectionStatus(Connection conexao, Packet pkt){
		/**
		 * Calcula o status e flags da conexão.
		 * O status serve para definir o timeout corretamente. 
		 * As Flags servem para a classificação nas técnicas de I.C
		 * 
		 * Based on:
		 * An Efficient TCP Flow State Management Algorithm in High-speed Network - Xiong Bing, Chen Xiaosu, Chen Ning
		 * 
		 * Possible flags:
		 * SO = Connection attempt seen, no reply. 
		 * S1 = Connection established, not terminated.
		 * S2 = Connection established and close attempt by originator seen, but no reply from responder.
		 * S3 = Connection established and close attempt by responder seen, but no reply from originator
		 * SF = The connection was normally established and terminated.
		 * REJ = Connection attempt rejected.
		 * RSTO = Connection established, originator aborted by sending a RST.
		 * RSTR = Connection established, responder aborted by sending a RST.
		 * RSTOSO = Originator sent a SYN followed by RST, we never saw a SYN ACK from the responder.
		 * RSTRH = Responder sent a SYN ACK flowed by a RST, we never saw a SYN from the originator.
		 * SH = Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder.
		 * SHR = Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
		 * OTH = Midstream traffic, we never saw a SYN.
		 */			
						
		if(conexao.getConnectionStatus().equals("Unknown")){
			if(pkt.getSYN() == true || pkt.getSYNACK() == true){
				conexao.setConnectionStatus("Handshake");
				conexao.setFlagConexao("S0");
			} else if (pkt.getACK() ==  true){
				conexao.setConnectionStatus("Established");
				conexao.setFlagConexao("S1");
			} else if (pkt.getFIN() == true){ 
				conexao.setConnectionStatus("Termination");
				if(pkt.getDirection().equals(Config.TAG_SourceToDest)){
					conexao.setFlagConexao("SH");
				} else {
					conexao.setFlagConexao("SHR");
				}
			} else {
				conexao.setConnectionStatus("Other");
				conexao.setFlagConexao("OTH");
			}											
			
		} else if (conexao.getConnectionStatus().equals("Handshake")){						
			if(pkt.getRST()){
				conexao.setConnectionStatus("Closed");
				if(pkt.getDirection().equals(Config.TAG_SourceToDest)){
					conexao.setFlagConexao("RSTOSO");
				} else {
					conexao.setFlagConexao("RSTRH");
				}
				
			} else if(pkt.getSYNACK()){
				return(conexao);

			} else if (pkt.getFIN()){
				conexao.setConnectionStatus("Termination");
				if(pkt.getDirection().equals(Config.TAG_SourceToDest)){
					conexao.setFlagConexao("SH");
				} else {
					conexao.setFlagConexao("SHR");
				}
				
			} else if (pkt.getACK()){
				conexao.setConnectionStatus("Established");
				conexao.setFlagConexao("S1");
			
			} else {
				conexao.setConnectionStatus("Other");
				conexao.setFlagConexao("OTH");				
			}						
						
		} else if (conexao.getConnectionStatus().equals("Established")){
			if(pkt.getACK()){
				return(conexao);
			} else if(pkt.getFIN()){
				conexao.setConnectionStatus("Termination");
				if (pkt.getDirection().equals(Config.TAG_SourceToDest)){					
					conexao.setFlagConexao("S2");
				} else {
					conexao.setFlagConexao("S3");
				}																				
			} else if (pkt.getRST()){
				conexao.setConnectionStatus("Closed");
				if (pkt.getDirection().equals(Config.TAG_SourceToDest)){					
					conexao.setFlagConexao("RSTO");
				} else {
					conexao.setFlagConexao("RSTR");
				}
			}				
			
		} else if (conexao.getConnectionStatus().equals("Termination")){
			if(pkt.getACK()){
				conexao.setConnectionStatus("Closed");
				conexao.setFlagConexao("SF");
			} else {
				return(conexao);
			}
			
		} else if (conexao.getConnectionStatus().equals("Closed")){
			return(conexao);			
		}
		return(conexao);
	}
	
	
	private synchronized void addPktInConnection(Packet pkt, String unique_id){
		Connection conexao = null;
		synchronized (conexoes) {
			try {
				conexao = conexoes.get(unique_id);
			} catch (Exception e) {
				return;
			}
		}
		conexao.setUltimoTS(pkt.getTimestamp());
		conexao.setVirtualTS(pkt.getTimestamp());				
		conexao.setDuration(TimeUnit.MILLISECONDS.toSeconds((conexao.getUltimoTS().getTime() - conexao.getPrimeiroTS().getTime())));
				
		if(conexao.getProtocol().equals(Config.TAG_ICMP) == false){
			conexao.addWrong(pkt.getWrong());
			conexao.addUrgptr(pkt.getUrgptr());
		}
							
		/**
		 * Define a direção do pacote.
		 */
		if(pkt.getIPsrc().equals(conexao.getIPsource())){
			pkt.setDirection(Config.TAG_SourceToDest);
			if(pkt.getProtocol().equals(Config.TAG_ARP) == false){
				conexao.setSTTL(pkt.getTTL());
			}
			conexao.addSourceToDestPkts();
			conexao.addSizeFromSourceToDest(pkt.getLength());
		} else {
			pkt.setDirection(Config.TAG_DestToSource);
			if(pkt.getProtocol().equals(Config.TAG_ARP) == false){
				conexao.setDTTL(pkt.getTTL());
			}
			conexao.addDestToSourcePkts();
			conexao.addSizeFromDestToSource(pkt.getLength());
		}
		
		conexao.addPacketCounter();
		
		if(conexao.getProtocol().equals(Config.TAG_TCP)){
			conexao = updateConnectionStatus(conexao, pkt);
			if(conexao.getConnectionStatus().equals("Handshake")){
				conexao.setTimeout(Config.TIMEOUT_TCP_HANDSHAKE);
			} else if(conexao.getConnectionStatus().equals("Established")){
				conexao.setTimeout(Config.TIMEOUT_TCP_ESTABLISHED);
			} else if(conexao.getConnectionStatus().equals("Termination")){
				conexao.setTimeout(Config.TIMEOUT_TCP_TERMINATION);
			} else if(conexao.getConnectionStatus().equals("Closed")){
				conexao.setTimeout(Config.TIMEOUT_TCP_CLOSED);
			} else {
				conexao.setTimeout(Config.TIMEOUT_OTHER);
			}
		} else if (conexao.getProtocol().equals(Config.TAG_UDP)){
			conexao.setTimeout(Config.TIMEOUT_UDP);
		} else if(conexao.getProtocol().equals(Config.TAG_ARP)){
			conexao.setTimeout(Config.TIMEOUT_ARP);
		} else {
			conexao.setTimeout(Config.TIMEOUT_ICMP);
		}
		
		if(conexao.getDont_Analyse() == true){
			conexao.setTimeout(Config.TIMEOUT_DONT_ANALYSE);
		}
				
		synchronized (conexoes) {
			conexoes.remove(unique_id);
			conexoes.put(unique_id, conexao);
		}																										
	}

		
	@SuppressWarnings("unchecked")
	private void createConnection(Packet pkt, String unique_id){
		Connection conexao = new Connection();				
		conexao.setProtocol(pkt.getProtocol());
		conexao.setUnique_id(unique_id);
		
		if(conexao.getProtocol().equals(Config.TAG_TCP)){
			conexao.setUrgptr(pkt.getUrgptr());
			if(pkt.getSYNACK() == true){
				conexao.setIPsource(pkt.getIPdst());
				conexao.setSport(pkt.getDport());			
				conexao.setIPdestination(pkt.getIPsrc());			
				conexao.setDport(pkt.getSport());	
				conexao.setSizeFromDestToSource(pkt.getLength());
				conexao.addDestToSourcePkts();
				conexao.setSizeFromSourceToDest(0);
				conexao.setDTTL(pkt.getTTL());
				pkt.setDirection(Config.TAG_DestToSource);				
			} else {
				conexao.setIPsource(pkt.getIPsrc());
				conexao.setSport(pkt.getSport());			
				conexao.setIPdestination(pkt.getIPdst());			
				conexao.setDport(pkt.getDport());
				conexao.setSizeFromDestToSource(0);
				conexao.setSizeFromSourceToDest(pkt.getLength());
				conexao.addSourceToDestPkts();
				conexao.setSTTL(pkt.getTTL());
				pkt.setDirection(Config.TAG_SourceToDest);
			}			
		} else if (conexao.getProtocol().equals(Config.TAG_UDP) || conexao.getProtocol().equals(Config.TAG_ICMP)){
			conexao.setIPsource(pkt.getIPsrc());
			conexao.setSport(pkt.getSport());			
			conexao.setIPdestination(pkt.getIPdst());			
			conexao.setDport(pkt.getDport());
			conexao.setSizeFromDestToSource(0);
			conexao.setSizeFromSourceToDest(pkt.getLength());
			conexao.addSourceToDestPkts();
			conexao.setSTTL(pkt.getTTL());
			pkt.setDirection(Config.TAG_SourceToDest);
		} else if (conexao.getProtocol().equals(Config.TAG_ARP)){
			conexao.setIPsource(pkt.getIPsrc());			
			conexao.setIPdestination(pkt.getIPdst());			
			conexao.setSizeFromDestToSource(0);
			conexao.setSizeFromSourceToDest(pkt.getLength());
			conexao.addSourceToDestPkts();
			pkt.setDirection(Config.TAG_SourceToDest);
		}
		
		if (pkt.getIPsrc() == pkt.getIPdst() && pkt.getSport() == pkt.getDport()){
			conexao.setLand(1);
    	} else {
    		conexao.setLand(0);
    	}				
			
		conexao.setPrimeiroTS(pkt.getTimestamp());
		conexao.setUltimoTS(pkt.getTimestamp());
		conexao.setVirtualTS(pkt.getTimestamp());		
		
		
		conexao.setTimeouted(false);
		conexao.addPacketCounter();
		if(pkt.getProtocol().equals(Config.TAG_TCP)){			
			/**
			 * Foi definido como 20 segundos porque quando cria a conexão presume-se que esteja em handshake
			 */
			conexao.setTimeout(Config.TIMEOUT_TCP_HANDSHAKE);
			conexao = updateConnectionStatus(conexao, pkt);
			conexao.setService(defineService(conexao.getDport(), conexao.getSport()));
			conexao.setWrong(pkt.getWrong());
		} else if (pkt.getProtocol().equals(Config.TAG_UDP)){
			conexao.setFlagConexao(Config.FLAG_UDP);
			conexao.setConnectionStatus("Closed");			
			conexao.setTimeout(Config.TIMEOUT_UDP);
			conexao.setWrong(pkt.getWrong());
			conexao.setService(defineService(conexao.getDport(), conexao.getSport()));
		} else if (pkt.getProtocol().equals(Config.TAG_ARP)){
			conexao.setTimeout(Config.TIMEOUT_ARP);
			conexao.setService(Config.TAG_ARP);
			conexao.setFlagConexao(Config.FLAG_ARP);
		} else { //ICMP
			conexao.setTimeout(Config.TIMEOUT_ICMP);
			conexao.setService(Config.TAG_ICMP);
			conexao.setFlagConexao(Config.FLAG_ICMP);
		}		
		
		if(conexoes.size() < Config.TAM_BUFFER){
			conexao.setDont_Analyse(true);
			conexao.setTimeout(Config.TIMEOUT_DONT_ANALYSE);
		}
			
		//{TIMESTAMP -- PROTOCOL -- IP_SOURCE:SOURCE_PORT -- IP_DEST:DEST_PORT}
		SimpleDateFormat format = new SimpleDateFormat("dd/MM/yyyy HH");		
		pkt.setVirtualTimestamp(format.format(pkt.getTimestamp()));		
		conexao.setVirtualUniqueID(pkt.getVirtualTimestamp()+"--"+conexao.getProtocol()+"--"+conexao.getIPsource()+":"+conexao.getSport()+"--"+conexao.getIPdestination()+":"+conexao.getDport());
		conexao.setReverseVirtualUniqueID(pkt.getVirtualTimestamp()+"--"+conexao.getProtocol()+"--"+conexao.getIPdestination()+":"+conexao.getDport()+"--"+conexao.getIPsource()+":"+conexao.getSport());
			
		LinkedHashMap<String, Connection> conexoes_temp = null;
		synchronized (conexoes) {
			 conexoes_temp = (LinkedHashMap<String, Connection>) conexoes.clone();		
		}										
		conexao.parm_time = Output.getTimeBuffer(conexao, conexoes_temp);
		conexao.parm_connections = Output.getConnectionsBuffer(conexao, conexoes_temp);
		conexoes_temp = null;
		synchronized (conexoes) {
			conexoes.put(unique_id , conexao);
		}
	}
	
	private String defineService(int Dport, int Sport){
		String service = "";		
		if(Config.services.containsKey(Dport) == true){
			service = Config.services.get(Dport);
		} else if(Config.services.containsKey(Sport) == true){
			service = Config.services.get(Sport);
		} else {
			service = "OTHER";
		}											
		return(service);
	}
}			