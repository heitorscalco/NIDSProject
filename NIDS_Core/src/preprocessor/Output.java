package preprocessor;

import java.util.LinkedHashMap;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import capturator.Connection;
import manager.ConnectionsManager;
import preprocessor.Config;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import preprocessor.Communicator;


public class Output {
		
	public synchronized static void writeInFile(String string) throws IOException {
		FileWriter arquivo = new FileWriter(Config.PATH_TO_OUTPUT, true);		
		PrintWriter gravarArq = new PrintWriter(arquivo);
		gravarArq.printf("%s\n",string);						
		arquivo.close();					
	}
	
	public synchronized void outputTreatment(Connection conexao) throws IOException, InterruptedException{				
		if(conexao.getDont_Analyse() == false){
			String parametros = "";
//			System.out.printf("SENT! %s -- %s:%d - %s:%d (%s)-- Status: %s  Flag: %s -- N. Pkts: %s -- ID: %s \n", conexao.getProtocol(), conexao.getIPsource(), conexao.getSport(), conexao.getIPdestination(), conexao.getDport(), conexao.getService(),conexao.getConnectionStatus(), conexao.getFlagConexao(), conexao.getNumOfPackets(), conexao.getUnique_id());
		
			
			parametros =	Float.toString(conexao.getDuration())+Config.SEPARATOR+
							conexao.getProtocol()+Config.SEPARATOR+
							conexao.getService()+Config.SEPARATOR+
							conexao.getFlagConexao()+Config.SEPARATOR+
							Integer.toString(conexao.getSizeFromSourceToDest())+Config.SEPARATOR+
							Integer.toString(conexao.getSizeFromDestToSource())+Config.SEPARATOR+
							Integer.toString(conexao.getLand())+Config.SEPARATOR+
							Integer.toString(conexao.getWrong())+Config.SEPARATOR+
							Integer.toString(conexao.getUrgptr())+Config.SEPARATOR+
							Integer.toString(conexao.getSTTL())+Config.SEPARATOR+
							Integer.toString(conexao.getDTTL())+Config.SEPARATOR+
							Integer.toString(conexao.getSourceToDestPkts())+Config.SEPARATOR+
							Integer.toString(conexao.getDestToSourcePkts())+Config.SEPARATOR;
								
			parametros = parametros + conexao.parm_time + conexao.parm_connections;
								
			if(Config.INCLUDE_LABELS){
				if(Config.INCLUDE_LABELS_FILE){
					synchronized (Config.CONNECTIONS_LABELED) {
						if(Config.CONNECTIONS_LABELED.containsKey(conexao.getVirtualUniqueID()) == true){
							if(Config.CONNECTIONS_LABELED.get(conexao.getVirtualUniqueID()).equals("Normal")){
								parametros = parametros + Config.TAG_NORMAL+Config.TERMINATOR;
							} else {
								parametros = parametros + Config.TAG_ATTACK+Config.TERMINATOR;
							}
							writeInFile(parametros);	
						} else if (Config.CONNECTIONS_LABELED.containsKey(conexao.getReverseVirtualUniqueID()) == true){
							 if(Config.CONNECTIONS_LABELED.get(conexao.getReverseVirtualUniqueID()).equals("Normal")){
								 parametros = parametros + Config.TAG_NORMAL+Config.TERMINATOR; 
							 } else {							 
								 parametros = parametros + Config.TAG_ATTACK+Config.TERMINATOR;
							 }
							writeInFile(parametros);	
						} else {
							System.out.println("Key NOT FOUND: "+ conexao.getVirtualUniqueID());
							parametros = parametros + Config.TAG_DEFAULT+Config.TERMINATOR+"NOT_FOUND";
						}
					}
				} else {
					parametros = parametros + Config.TAG_DEFAULT+Config.TERMINATOR;
					writeInFile(parametros);
				}
				
			} else if(Config.ENABLE_SOCKET == true && Config.CAPTURE_ONLINE == true){ 
				send_through_socket(parametros);
				System.out.printf("SENT! %s -- %s:%d - %s:%d (%s)-- Status: %s  Flag: %s -- N. Pkts: %s -- ID: %s \n", conexao.getProtocol(), conexao.getIPsource(), conexao.getSport(), conexao.getIPdestination(), conexao.getDport(), conexao.getService(),conexao.getConnectionStatus(), conexao.getFlagConexao(), conexao.getNumOfPackets(), conexao.getUnique_id());
			} else {
				parametros = parametros + Config.TERMINATOR;
			}
		} else {
//			System.out.printf("DELETED! %s -- %s:%d - %s:%d (%s)-- Status: %s  Flag: %s -- N. Pkts: %s -- ID: %s \n", conexao.getProtocol(), conexao.getIPsource(), conexao.getSport(), conexao.getIPdestination(), conexao.getDport(), conexao.getService(),conexao.getConnectionStatus(), conexao.getFlagConexao(), conexao.getNumOfPackets(), conexao.getUnique_id());
		} 
		
		synchronized (ConnectionsManager.conexoes) {
			ConnectionsManager.conexoes.remove(conexao.getUnique_id());
		}
	}		
		
	private synchronized void send_through_socket(String parametros){
		try {
			Communicator.sendMessage(parametros);
		} catch (Exception e) {
			System.out.println("Socket Error " + e);
		}					
	}
	
	public synchronized static String getTimeBuffer(Connection conexao, LinkedHashMap<String, Connection> buffer){
		String parameters = null;
		long primeiro_ts = conexao.getPrimeiroTS().getTime();
		int count_same_host = 0, 
			count_same_service = 0, 
			count_diff_service = 0,
			count_same_host_syn_error = 0,
			count_same_service_syn_error = 0;
		
		
		if(buffer.isEmpty() == false){			
		    Set<String> sorted_connection_keys = buffer.keySet();
		    long diferenca = primeiro_ts - TimeUnit.SECONDS.toMillis(Config.TIME);
		    
		    for(int i=1; i<=buffer.size(); i++){		    			    		    			    			    			
	    		if (buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getPrimeiroTS().getTime() > diferenca){	    			
	    			/**
	    			 * Same host connections
	    			 */
	    			if((buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getIPdestination().equals(conexao.getIPdestination()) == true) ||
	    			   (buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getIPsource().equals(conexao.getIPdestination()) == true)) {
	    				count_same_host++;
	    				/**
	    				 * serror_rate = % of connections that have ``SYN'' errors 	
	    				 */	    		   			
	    				if((buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getConnectionStatus() == "Handshake") || 
	    				   (buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getSYN() > 2)){	    					
	    					count_same_host_syn_error++;
	    				} 	    					    					    				    				    			
	    			} 
	    			
	    			/**
	    			 * Same Service Connections
	    			 */	    			
	    			if(buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getService().equals(conexao.getService()) == true ){
	    				/**
	    				 * srv_count = number of connections to the same service as the current connection in the past two seconds 	
	    				 */
	    				count_same_service++;
    					
    					/**
    					 * srv_serror_rate = % of connections that have ``SYN'' errors
    					 */
	    				if((buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getConnectionStatus() == "Handshake") || 
 	    				   (buffer.get(sorted_connection_keys.toArray()[buffer.size()-i]).getSYN() > 2)){
 	    					
 	    					count_same_service_syn_error++;
 	    				}   			    
    				} else {
    					count_diff_service++;
    				}	    					    					    				    				    				  
	    		} else {
	    			/**
	    			 * Iterator will never find more connections
	    			 */
	    			break; 
	    		}	    			    			   	   	    		
	    	}	    	
	    }
		
		
		/**
		 	count: continuous. 
			srv_count: continuous.
			serror_rate: continuous. 
			srv_serror_rate: continuous.			
			same_srv_rate: continuous.
			diff_srv_rate: continuous.			
			srv_diff_host_rate: continuous.
		 */
				
		parameters = 	Integer.toString(count_same_host)+Config.SEPARATOR+
						Integer.toString(count_same_service)+Config.SEPARATOR+ 
						
						//SYN ERROR
						percentageCalculation(count_same_host, count_same_host_syn_error)+Config.SEPARATOR+
						percentageCalculation(count_same_service, count_same_service_syn_error)+Config.SEPARATOR+
						
						//Same Service Rate	
						percentageCalculation((count_same_service+count_diff_service), count_same_service)+Config.SEPARATOR+
						percentageCalculation((count_same_service+count_diff_service), count_diff_service)+Config.SEPARATOR+
																	
						//Same Service Different Host Rate
						percentageCalculation(count_same_service, count_diff_service)+Config.SEPARATOR;
		return(parameters);
	}	
	
	private synchronized static String percentageCalculation(int count, int parm){
		if(count>0){
			return(Float.toString((100*parm)/count));
		} else {
			return("0");
		}		
	}
	
//	public synchronized String getConnectionsBuffer(Conexao conexao, String parameters){
	public synchronized static String getConnectionsBuffer(Connection conexao, LinkedHashMap<String, Connection> buffer){		
		/**
		 * 	Some probing attacks scan the hosts (or ports) using a much larger time interval than two seconds, 
		 * 	for example once per minute.  Therefore, connection records were also sorted by destination host, 
		 * 	and features were constructed using a window of 100 connections to the same host instead of a time window.  
		 * 		dst_host_count: continuous.
				dst_host_srv_count: continuous.
				dst_host_same_srv_rate: continuous.
				dst_host_diff_srv_rate: continuous.
				dst_host_same_src_port_rate: continuous.
				dst_host_srv_diff_host_rate: continuous.
				dst_host_serror_rate: continuous.
				dst_host_srv_serror_rate: continuous.
				dst_host_rerror_rate: continuous. -> Removed
				dst_host_srv_rerror_rate: continuous. -> Removed
		 */
		
	
		String parameters = null;
		int count = 0,
			serror_rate = 0,
			same_srv_rate = 0,
			diff_srv_rate = 0,
			
			srv_count = 0,			
			srv_serror_rate = 0,
			srv_diff_host_rate = 0,			
			same_src_port_rate = 0;		
		
		//Contador do tamanho do Buffer
	    int counter = (buffer.size() < Config.TAM_BUFFER) ? buffer.size() : Config.TAM_BUFFER;
		if(buffer.isEmpty() == false){								    						 		    		  
		    for(int i=1; i<=counter; i++){		    
		    		    	
		    	/**
		    	 * Same Destination
		    	 */
		    	if(buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getIPdestination().equals(conexao.getIPdestination()) == true ||
		    	   buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getIPsource().equals(conexao.getIPdestination()) == true ){
		    		count++;
		    		
		    		/**
    				 * serror_rate = % of connections that have ``SYN'' errors 	
    				 */	    		   			
    				if((buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getConnectionStatus() == "Handshake") || 
    				   (buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getSYN() > 2)){	    					    					
						serror_rate++;    					    						
    				}    					
    				
    				/** 
    		    	 * Same Service
    		    	 */
    		    	if(buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getService().equals(conexao.getService()) == true){
    		    		same_srv_rate++;		      		    		    		    	    		    		    		        		    		
    		    	} else {
    		    		diff_srv_rate++;
    		    	}    		    	    		    	    						   
		    	}
		    	 	
		    			    	
		    	/** 
		    	 * Same Service
		    	 */
		    	if(buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getService().equals(conexao.getService()) == true ){
		    		srv_count++;		  
		    		
		    		/**
    				 * serror_rate = % of connections that have ``SYN'' errors 	
    				 */	    		   			
    				if((buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getConnectionStatus() == "Handshake") || 
    				   (buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getSYN() > 2)){	    					    					
						srv_serror_rate++;    					    						
    				}
    				
    				/**
    				 * Different hosts
    				 */
    				if( (buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getIPdestination().equals(conexao.getIPdestination()) == false) &&
    					(buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getIPsource().equals(conexao.getIPdestination()) == false)) {
    		    		srv_diff_host_rate++;        	
    		    	}    				    						    		    		
		    	} 
		    			    	
		    	if(buffer.get(buffer.keySet().toArray()[buffer.size()-i]).getSport() == conexao.getSport()){
		    		same_src_port_rate++;
		    	}		    			    			    			  
		    }	    	
	    }
						
		parameters = 	//Counters								
						Integer.toString(count)+Config.SEPARATOR+
						Integer.toString(srv_count)+Config.SEPARATOR+ 
						
						//Same/Different Services Rate
						percentageCalculation(count, same_srv_rate)+Config.SEPARATOR+
						percentageCalculation(count, diff_srv_rate)+Config.SEPARATOR+
						
						//Same source port
						percentageCalculation(counter, same_src_port_rate)+Config.SEPARATOR+
						
						//Same Service Different Host
						percentageCalculation(srv_count, srv_diff_host_rate)+Config.SEPARATOR+
						
						//Syn Errors
						percentageCalculation(count, serror_rate)+Config.SEPARATOR+
						percentageCalculation(srv_count, srv_serror_rate)+Config.SEPARATOR;
						
		return(parameters);
	}
			
}